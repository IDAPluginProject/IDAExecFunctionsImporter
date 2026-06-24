#pragma once

#include <string>

#include <kernwin.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <idp.hpp>
#include <hexrays.hpp>

#include <Import/ExecSignatures.hpp>

static const char ExecRenameActionName[] = "idamappings:rename_exec_target";

// "APawn::execGetLocalViewingPlayerController" -> "APawn::GetLocalViewingPlayerController"
// Returns an empty string when the last name component has no 'exec' prefix
inline std::string DeriveRealNameFromExecThunk(const std::string& RawThunkName)
{
	std::string ThunkName = RawThunkName;
	const size_t ParamStart = ThunkName.find('(');
	if (ParamStart != std::string::npos)
		ThunkName.erase(ParamStart);

	const size_t ScopeEnd = ThunkName.rfind("::");
	const size_t FuncStart = (ScopeEnd == std::string::npos) ? 0 : ScopeEnd + 2;

	const std::string Scope    = ThunkName.substr(0, FuncStart);
	const std::string FuncPart = ThunkName.substr(FuncStart);

	if (FuncPart.rfind("exec", 0) != 0 || FuncPart.length() <= 4)
		return std::string();

	return Scope + FuncPart.substr(4);
}

inline std::string StripReturnTypeSuffix(std::string Name, const std::string& ReturnType)
{
	const auto TryStrip = [&Name](const std::string& Token) -> bool
	{
		const std::string Suffix = "_" + Token + "_";

		if (Name.size() > Suffix.size() && Name.compare(Name.size() - Suffix.size(), Suffix.size(), Suffix) == 0)
		{
			Name.erase(Name.size() - Suffix.size());
			return true;
		}

		return false;
	};

	// Prefer the exact return type from the signature
	if (!ReturnType.empty())
	{
		std::string Bare = ReturnType;

		while (!Bare.empty() && (Bare.back() == '*' || Bare.back() == ' '))
			Bare.pop_back();

		if (TryStrip(Bare))
			return Name;
	}

	// Fallback to common primitive return types when no signature is available
	static const char* const Primitives[] = {
		"void", "bool", "char", "float", "double", "int",
		"int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64",
	};

	for (const char* Token : Primitives)
		if (TryStrip(Token))
			return Name;

	return Name;
}

struct ExecRenameActionHandler : public action_handler_t
{
	int idaapi activate(action_activation_ctx_t* Context) override
	{
		// The symbol under the cursor is the inner sub_XXXX we want to rename
		qstring HighlightedText;
		uint32 HighlightFlags = 0;
		if (!get_highlight(&HighlightedText, Context->widget, &HighlightFlags) || HighlightedText.empty())
		{
			msg("[IDAMappingsImporter] Put the cursor on the inner function call first.\n");
			return 0;
		}

		const ea_t TargetAddress = get_name_ea(BADADDR, HighlightedText.c_str());
		if (TargetAddress == BADADDR)
		{
			msg("[IDAMappingsImporter] '%s' is not a resolvable address.\n", HighlightedText.c_str());
			return 0;
		}

		// The function the cursor sits in should be the exec thunk
		func_t* ThunkFunction = get_func(get_screen_ea());
		if (ThunkFunction == nullptr)
		{
			msg("[IDAMappingsImporter] Not inside a function.\n");
			return 0;
		}

		if (TargetAddress == ThunkFunction->start_ea)
		{
			msg("[IDAMappingsImporter] That's the exec thunk itself, please highlight the inner function call.\n");
			return 0;
		}

		// The rename target must be a real function start (the inner sub), not an arbitrary symbol
		func_t* TargetFunc = get_func(TargetAddress);
		if (TargetFunc == nullptr || TargetFunc->start_ea != TargetAddress)
		{
			msg("[IDAMappingsImporter] '%s' doesn't resolve to a function start, highlight the inner call.\n", HighlightedText.c_str());
			return 0;
		}

		// And it must actually be called from inside this exec thunk and not just any function whose name happens to be highlighted while the cursor is in the thunk
		bool bCalledFromThunk = false;
		for (ea_t Ref = get_first_cref_to(TargetAddress); Ref != BADADDR; Ref = get_next_cref_to(TargetAddress, Ref))
		{
			if (func_contains(ThunkFunction, Ref))
			{
				bCalledFromThunk = true;
				break;
			}
		}

		if (!bCalledFromThunk)
		{
			msg("[IDAMappingsImporter] '%s' isn't called from this exec thunk, highlight the inner call.\n", HighlightedText.c_str());
			return 0;
		}

		qstring ThunkName;
		get_func_name(&ThunkName, ThunkFunction->start_ea);

		// Exec thunks are stored mangled; demangle to the short form so we can find 'exec'
		qstring DemangledThunkName;
		if (demangle_name(&DemangledThunkName, ThunkName.c_str(), MNG_SHORT_FORM) > 0 && !DemangledThunkName.empty())
			ThunkName = DemangledThunkName;

		std::string RealName = DeriveRealNameFromExecThunk(ThunkName.c_str());
		if (RealName.empty())
		{
			msg("[IDAMappingsImporter] '%s' is not an exec thunk (no 'exec' prefix found).\n", ThunkName.c_str());
			return 0;
		}

		// Look up the signature first: it both cleans the name and supplies the prototype
		auto& Signatures = CurrentIdbSignatures();
		const auto SignatureIt = Signatures.find(ThunkFunction->start_ea);
		const std::string SignatureReturnType = (SignatureIt != Signatures.end()) ? SignatureIt->second.ReturnType : std::string();

		RealName = StripReturnTypeSuffix(RealName, SignatureReturnType);

		if (set_name(TargetAddress, RealName.c_str(), SN_FORCE | SN_NOCHECK | SN_NOWARN))
			msg("[IDAMappingsImporter] 0x%llX -> %s\n", static_cast<uint64>(TargetAddress), RealName.c_str());
		else
			msg("[IDAMappingsImporter] Failed to rename 0x%llX to %s\n", static_cast<uint64>(TargetAddress), RealName.c_str());

		// Apply the real prototype if the import recorded a signature for this thunk
		if (SignatureIt != Signatures.end())
		{
			std::string ClassName;

			const std::string ThunkNameStr(ThunkName.c_str());
			const size_t ScopeSep = ThunkNameStr.rfind("::");

			if (ScopeSep != std::string::npos)
				ClassName = ThunkNameStr.substr(0, ScopeSep);

			if (ApplyExecSignature(TargetAddress, ClassName, SignatureIt->second))
				msg("[IDAMappingsImporter]   prototype applied.\n");
		}

		// Redecompile the current view so the rename + prototype show without a manual F5
		if (init_hexrays_plugin())
		{
			mark_cfunc_dirty(TargetAddress, false);

			if (vdui_t* CurrentView = get_widget_vdui(Context->widget))
				CurrentView->refresh_view(true);
		}

		return 1;
	}

	action_state_t idaapi update(action_update_ctx_t* Context) override
	{
		const int WidgetType = Context->widget_type;
		return (WidgetType == BWN_DISASM || WidgetType == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
	}
};

struct ExecRenameUiListener : public event_listener_t
{
	ssize_t idaapi on_event(ssize_t NotificationCode, va_list Arguments) override
	{
		if (NotificationCode == ui_finish_populating_widget_popup)
		{
			TWidget* Widget   = va_arg(Arguments, TWidget*);
			TPopupMenu* Popup = va_arg(Arguments, TPopupMenu*);

			const int WidgetType = get_widget_type(Widget);
			if (WidgetType == BWN_DISASM || WidgetType == BWN_PSEUDOCODE)
				attach_action_to_popup(Widget, Popup, ExecRenameActionName);
		}
		return 0;
	}
};

inline ExecRenameActionHandler GExecRenameHandler;
inline ExecRenameUiListener    GExecRenameListener;
inline int                     GExecRenameRefCount = 0;

inline void InstallExecRenameAction()
{
	if (GExecRenameRefCount++ > 0)
		return;

	const action_desc_t Desc = ACTION_DESC_LITERAL_OWNER(
		ExecRenameActionName,
		"Rename UE exec target function",
		&GExecRenameHandler,
		nullptr,        // no plugmod owner: the action is process-wide
		"Alt-U",
		"Rename the highlighted sub_XXXX to the real UE function (from the enclosing exec thunk)",
		-1,
		ADF_GLOBAL);

	register_action(Desc);
	hook_event_listener(HT_UI, &GExecRenameListener, nullptr);
}

inline void UninstallExecRenameAction()
{
	if (GExecRenameRefCount <= 0 || --GExecRenameRefCount > 0)
		return;

	unhook_event_listener(HT_UI, &GExecRenameListener);
	unregister_action(ExecRenameActionName);
}
