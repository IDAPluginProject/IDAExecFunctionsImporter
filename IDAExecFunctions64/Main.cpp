#include <fstream>
#include <stop_token>
#include <vector>
#include <cstring>
#include <Windows.h>

#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <srclang.hpp>
#include <search.hpp>
#include <xref.hpp>
#include <allins.hpp>
#include <strlist.hpp>
#include <unordered_set>

#include <Format/Format.hpp>
#include <Import/MappingsImporter.hpp>

#include <filesystem>

namespace fs = std::filesystem;

enum class EAvailableFoldersStatus : uint8
{
	None,        // neither subfolder present, or the selection was invalid
	All,         // both CppSDK and IDAMappings are present
	CppSDK,      // only CppSDK is present
	IDAMappings  // only IDAMappings is present
};

std::pair<fs::path, EAvailableFoldersStatus> AskForSDKFolder(fs::path DefaultPath)
{
	qstring FolderQStr = DefaultPath.string().c_str();

	if (!ask_str(&FolderQStr, HIST_DIR, "Please select a folder containing \"CppSDK\" and \"IDAMappings\" subfolders."))
		return std::pair{ std::string{}, EAvailableFoldersStatus::None };

	fs::path Folder;
	Folder = FolderQStr.c_str();

	fs::path CppSDKPath = Folder / "CppSDK";
	fs::path IDAMappingsPath = Folder / "IDAMappings";

	const bool bhasCppSDKFolder      = fs::exists(CppSDKPath) && fs::is_directory(Folder / "CppSDK");
	const bool bhasIDAMappingsFolder = fs::exists(IDAMappingsPath) && fs::is_directory(Folder / "IDAMappings");

	if (!fs::exists(Folder) || !fs::is_directory(Folder) || (!bhasCppSDKFolder && !bhasIDAMappingsFolder))
	{
		warning("Please select the top level generated folder for your game that contains 'CppSDK' and 'IDAMappings'. Eg.'5.7.2-0+UE5-GameName'");
		return std::pair{ fs::path{}, EAvailableFoldersStatus::None };
	}

	if (!bhasCppSDKFolder)
	{
		warning("Selected folder doesn't contain 'CppSDK' folder, importing SDK.hpp into IDA won't be available.");
		return std::pair{ Folder, EAvailableFoldersStatus::IDAMappings };
	}

	if (!bhasIDAMappingsFolder)
	{
		warning("Selected folder doesn't contain 'IDAMappings' folder, importing VTables, ExecFunctions and global variables won't be available.");
		return std::pair{ Folder, EAvailableFoldersStatus::CppSDK };
	}

	return std::pair{ Folder, EAvailableFoldersStatus::All };
}

bool ParseSDKHeaderWithClang(const fs::path& HeaderPath)
{
	if (!select_parser_by_srclang(SRCLANG_CPP))
		return false;

	constexpr const char* ClangArgs = "-std=c++20 -Wno-invalid-offsetof -Wno-c++11-narrowing -D IMPORT_CPP_SDK_INTO_IDA=1";

	const int ParserErrorCode = set_parser_argv("clang", ClangArgs);
	if (ParserErrorCode != 0)
	{
		msg("ParseSDKHeaderWithClang: failed to set parser argv. ErrorCode: %d\n", ParserErrorCode);
		return false;
	}

	// nullptr for til => import straight into the current IDB
	const int NumCompilerErrors = parse_decls_with_parser("clang", nullptr, HeaderPath.string().c_str(), true);

	if (NumCompilerErrors == -1)
	{
		msg("ParseSDKHeaderWithClang: parser not found - is idaclang plugin loaded?\n");
		return false;
	}

	msg("ParseSDKHeaderWithClang: parsed '%s' with %d error(s)\n", HeaderPath.string().c_str(), NumCompilerErrors);
	return NumCompilerErrors == 0;
}

struct VTableEntry
{
	ea_t SlotAddress;   // address of the pointer slot in the vtable
	ea_t FuncAddress;   // address of the actual function
	int  Index;
};

static void IterateVTable(ea_t VTableAddress, std::function<void(const VTableEntry&)> Callback)
{
	const int PtrSize = inf_is_64bit() ? 8 : 4;
	int Index = 0;

	while (true)
	{
		ea_t SlotAddress = VTableAddress + (Index * PtrSize);

		// Stop at the next named item (new VTable, function, data symbol, etc.)
		if (Index > 0 && has_name(get_flags(SlotAddress)))
			break;

		ea_t FuncAddress = (PtrSize == 8)
			? get_qword(SlotAddress)
			: get_dword(SlotAddress);

		// Must point into a code segment
		segment_t* TargetSeg = getseg(FuncAddress);
		if (!TargetSeg || TargetSeg->sclass != SEG_CODE)
			break;

		// Slot itself must be a defined head (IDA has analysed it as data)
		if (Index > 0 && !is_head(get_flags(SlotAddress)))
			break;

		Callback({ SlotAddress, FuncAddress, Index });
		Index++;
	}
}

void SetFunctionThisPtrType(ea_t FuncAddress, tinfo_t ThisType)
{
	// Get the existing function type
	tinfo_t FuncType;
	if (!get_tinfo(&FuncType, FuncAddress))
	{
		// No type info yet, guess it from analysis
		guess_tinfo(&FuncType, FuncAddress);
	}

	func_type_data_t FuncData;
	if (!FuncType.get_func_details(&FuncData))
	{
		msg("Failed to get func details at 0x%llX\n", (uint64)FuncAddress);
		return;
	}

	// First arg is `this` for non-static member functions
	if (FuncData.empty())
	{
		// No args at all, insert one
		funcarg_t ThisArg;
		ThisArg.type = ThisType;
		ThisArg.name = "this";
		FuncData.push_back(ThisArg);
	}
	else
	{
		const tinfo_t& FirstArgType = FuncData[0].type;

		// Skip if the first parameter is already a pointer to a struct/class
		if (FirstArgType.is_ptr())
		{
			const tinfo_t PointeeType = FirstArgType.get_pointed_object();
			if (PointeeType.is_struct())
			{
				return;
			}
		}
		FuncData[0].type = ThisType;
		FuncData[0].name = "this";
	}

	FuncType.create_func(FuncData);
	apply_tinfo(FuncAddress, FuncType, TINFO_DEFINITE);
}

static void HandleVTableThisPtrRename(ea_t VTableAddress, ea_t SuperVTableAddress, std::string TypeName)
{
	tinfo_t StructType;
	if (!StructType.get_named_type(get_idati(), TypeName.c_str()))
		return; // type not imported (e.g. SDK.hpp not parsed) -> skip this-ptr typing silently

	tinfo_t ThisType;
	ThisType.create_ptr(StructType);

	auto CallSetFunctionThisPtr = [&](const VTableEntry& Entry)
	{
		const ea_t SuperFuncAddressSlot = SuperVTableAddress + Entry.Index * (inf_is_64bit() ? 8 : 4);

		if (SuperVTableAddress && Entry.FuncAddress == get_qword(SuperFuncAddressSlot))
		{
			return;
		}

		SetFunctionThisPtrType(Entry.FuncAddress, ThisType);
	};

	IterateVTable(VTableAddress, CallSetFunctionThisPtr);
}

static void LoadOldMapping(const std::vector<uint8_t>& Buffer, ea_t ImageBase)
{
	size_t Position = 0;
	const size_t Size = Buffer.size();

	while (Position + sizeof(uint32_t) + sizeof(uint16_t) <= Size)
	{
		uint32_t Offset;
		memcpy(&Offset, Buffer.data() + Position, sizeof(Offset));
		Position += sizeof(Offset);

		uint16_t NameLength;
		memcpy(&NameLength, Buffer.data() + Position, sizeof(NameLength));
		Position += sizeof(NameLength);

		if (Position + NameLength > Size)
			break;

		std::string Name(reinterpret_cast<const char*>(Buffer.data() + Position), NameLength);
		Position += NameLength;

		set_name(ImageBase + Offset, Name.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);

		if (Name.ends_with("_VFT"))
			HandleVTableThisPtrRename(ImageBase + Offset, 0, Name.substr(0, Name.length() - 4));
	}
}

bool ReadAndParseIDAMappings(const fs::path& IDAMappingsFilePath, bool bImportTypes)
{
	std::ifstream IDAMappingsFile(IDAMappingsFilePath, std::ios::binary | std::ios::ate);
	if (!IDAMappingsFile)
	{
		msg("[IDAMappingsImporter] Failed to open file!\n");
		return false;
	}

	const auto IDAMappingsFileSize = IDAMappingsFile.tellg();
	std::vector<uint8_t> Buffer(IDAMappingsFileSize);
	IDAMappingsFile.seekg(0);
	IDAMappingsFile.read(reinterpret_cast<char*>(Buffer.data()), IDAMappingsFileSize);

	const ea_t ImageBase = get_imagebase();

	if (!Buffer.empty() && Buffer[0] == MappingLayouts::FileMagic)
	{
		msg("[IDAMappingsImporter] Loading V2 mapping file...\n");
		LoadMappings(std::move(Buffer), ImageBase, bImportTypes);
	}
	else
	{
		msg("[IDAMappingsImporter] Loading V1 mapping file...\n");
		LoadOldMapping(Buffer, ImageBase);
	}

	msg("[IDAMappingsImporter] Done!\n");

	return true;
}

fs::path FindFileWithExtensionInPath(const fs::path& PathToSearch, std::string ExtensionString)
{
	if (!fs::exists(PathToSearch) || !fs::is_directory(PathToSearch))
	{
		return {};
	}

	// Normalize the extension: ensure it starts with a dot
	if (!ExtensionString.empty() && ExtensionString.front() != '.')
	{
		ExtensionString.insert(0, ".");
	}

	for (const fs::directory_entry& Entry : fs::recursive_directory_iterator(PathToSearch))
	{
		if (!Entry.is_regular_file())
		{
			continue;
		}

		if (Entry.path().extension() == ExtensionString)
		{
			return Entry.path();
		}
	}

	return {};
}

std::vector<ea_t> FindWideStringLiteralsByContent(const char* Str)
{
	std::vector<ea_t> Ret;

	if (!Str || Str[0] == '\0')
		return Ret;

	auto AddUniqueAddress = [&Ret](const ea_t Address)
	{
		if (Address != BADADDR && std::find(Ret.begin(), Ret.end(), Address) == Ret.end())
			Ret.push_back(Address);
	};

	std::vector<uchar> Pattern;
	for (const char* Ch = Str; *Ch; ++Ch)
	{
		Pattern.push_back(static_cast<uchar>(*Ch));
		Pattern.push_back(0);
	}
	Pattern.push_back(0);
	Pattern.push_back(0);

	for (int SegIdx = 0; SegIdx < get_segm_qty(); ++SegIdx)
	{
		segment_t* Seg = getnseg(SegIdx);
		if (!Seg || !(Seg->perm & SEGPERM_READ) || (Seg->perm & SEGPERM_EXEC))
			continue;

		ea_t SearchStart = Seg->start_ea;
		while (SearchStart < Seg->end_ea)
		{
			const ea_t Found = bin_search(
				SearchStart,
				Seg->end_ea,
				Pattern.data(),
				nullptr,
				Pattern.size(),
				BIN_SEARCH_FORWARD
			);

			if (Found == BADADDR)
				break;

			AddUniqueAddress(Found);
			SearchStart = Found + 1;
		}
	}

	return Ret;
}

std::unordered_set<func_t*> GetFunctionsReferencingThisFunction(const ea_t Address)
{
	std::unordered_set<func_t*> Ret;

	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(Address, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		if (func_t* Function = get_func(Xref.from))
			Ret.insert(Function);
	}

	return Ret;
}

std::unordered_set<func_t*> GetFunctionsReferencingAnyAddress(const std::vector<ea_t>& Addresses)
{
	std::unordered_set<func_t*> Ret;

	for (const ea_t Address : Addresses)
	{
		if (Address == BADADDR)
			continue;

		std::unordered_set<func_t*> Refs = GetFunctionsReferencingThisFunction(Address);
		Ret.insert(Refs.begin(), Refs.end());
	}

	return Ret;
}

// Collect all call targets inside a function's body, in address order.
static std::vector<ea_t> GetCallTargetsInFunc(func_t* Func)
{
	std::vector<ea_t> CallTargets;

	for (ea_t Addr = Func->start_ea; Addr < Func->end_ea; Addr = next_head(Addr, Func->end_ea))
	{
		if (!is_code(get_flags(Addr)))
			continue;

		insn_t Insn;
		if (decode_insn(&Insn, Addr) <= 0)
			continue;

		if (!is_call_insn(Insn))
			continue;

		const op_t& Op = Insn.ops[0];
		if (Op.type == o_near || Op.type == o_far)
			CallTargets.push_back(Op.addr);
		else if (Op.type == o_mem || Op.type == o_displ)
			CallTargets.push_back(Op.addr); // indirect — still record it
	}

	return CallTargets;
}

std::string WStrToStr(const std::wstring& WStr)
{
	if (WStr.empty())
		return std::string();

	const auto SizeNeeded = WideCharToMultiByte(CP_UTF8, 0, WStr.c_str(), static_cast<int>(WStr.size()), NULL, 0, NULL, NULL);

	std::string Str(SizeNeeded, 0);
	WideCharToMultiByte(CP_UTF8, 0, WStr.c_str(), static_cast<int>(WStr.size()), Str.data(), SizeNeeded, NULL, NULL);

	return Str;
}

bool IsUnrealScriptPackagePath(const std::wstring& WStr)
{
	return WStr.starts_with(L"/Script/");
}

static std::wstring ReadAsciiWideStringAt(ea_t Addr)
{
	if (Addr == BADADDR)
		return {};

	const uint16 FirstWord = get_word(Addr);
	if (FirstWord < 0x20 || FirstWord > 0x7E)
		return {};

	std::wstring Str;
	for (int CharIdx = 0; CharIdx < 512; ++CharIdx)
	{
		const uint16 Ch = get_word(Addr + CharIdx * 2);
		if (Ch == 0)
			break;
		if (Ch > 0x7E) // non-ASCII -> not the string we want
			return {};
		Str.push_back(static_cast<wchar_t>(Ch));
	}

	return Str;
}

static std::string GetStaticClassNameFromBodyCall(func_t* Func, ea_t BodyAddr)
{
	constexpr int RegRcx = 1;     // arg 1
	constexpr int RegRdx = 2;     // arg 2
	constexpr int NumGpRegs = 16; // rax..r15

	ea_t RegTarget[NumGpRegs];
	for (int i = 0; i < NumGpRegs; ++i)
		RegTarget[i] = BADADDR;

	for (ea_t Addr = Func->start_ea; Addr < Func->end_ea; Addr = next_head(Addr, Func->end_ea))
	{
		if (!is_code(get_flags(Addr)))
			continue;

		insn_t Insn;
		if (decode_insn(&Insn, Addr) <= 0)
			continue;

		// Track string pointers loaded into registers (directly, or copied between regs)
		if (Insn.ops[0].type == o_reg && Insn.ops[0].reg < NumGpRegs)
		{
			if (Insn.itype == NN_lea)
				RegTarget[Insn.ops[0].reg] = Insn.ops[1].addr;
			else if (Insn.itype == NN_mov && Insn.ops[1].type == o_reg && Insn.ops[1].reg < NumGpRegs)
				RegTarget[Insn.ops[0].reg] = RegTarget[Insn.ops[1].reg];
		}

		if (is_call_insn(Insn) && Insn.ops[0].type == o_near && Insn.ops[0].addr == BodyAddr)
		{
			const std::wstring Package = ReadAsciiWideStringAt(RegTarget[RegRcx]);
			const std::wstring Name = ReadAsciiWideStringAt(RegTarget[RegRdx]);

			// arg1 should be a "/Script/..." package path and arg2 is the class name
			if (!Name.empty() && (Package.empty() || IsUnrealScriptPackagePath(Package)))
				return WStrToStr(Name);

			for (int i = 0; i < NumGpRegs; ++i)
				RegTarget[i] = BADADDR;
		}
	}

	return {};
}

std::unordered_map<std::string, std::pair<char, uint8_t>> PrefixCache;


std::string GetPrefixedName(const std::string& ObjectName)
{
	auto It = PrefixCache.find(ObjectName);
	if (It != PrefixCache.end())
	{
		auto& [Prefix, AccessCounter] = It->second;
		return Prefix + ObjectName + (AccessCounter++ > 0 ? std::to_string(AccessCounter) : "");
	}

	return ObjectName;
}

std::string GetMangledFunctionNameForStaticclass(const std::string& ClassPrefixedName)
{
	return "_ZN" + std::to_string(ClassPrefixedName.length()) + ClassPrefixedName + "11" + "StaticClass" + "Ev";
}

void SetStaticClassNameAndSignature(func_t* Function, const std::string& ClassPrefixedName, tinfo_t& StaticClassFuncType)
{
	set_name(Function->start_ea, GetMangledFunctionNameForStaticclass(ClassPrefixedName).c_str(), SN_FORCE);

	tinfo_t FuncType;
	if (!get_tinfo(&FuncType, Function->start_ea))
	{
		// No type info yet — try to guess it first
		guess_tinfo(&FuncType, Function->start_ea);
	}

	apply_tinfo(Function->start_ea, StaticClassFuncType, TINFO_DEFINITE);
}

/**
 * Builds a function signature: UClass* FunctionName();
 * Matches Unreal Engine coding style.
 */
tinfo_t BuildStaticClassFuncType()
{
	tinfo_t UClassType;
	// Attempt to locate UClass in the IDB's type library.
	if (!UClassType.get_named_type(get_idati(), "UClass"))
	{
		UClassType.create_forward_decl(get_idati(), BTF_STRUCT, "UClass");
	}

	// Convert UClass to UClass*
	UClassType.create_ptr(UClassType);

	// Prepare the function prototype data.
	func_type_data_t FuncData;
	FuncData.clear();            // start from an empty prototype (no arguments)
	FuncData.rettype = UClassType;

	// Create the final function tinfo_t.
	tinfo_t FuncType;
	if (!FuncType.create_func(FuncData))
	{
		msg("Error: Failed to create function signature object.\n");
	}

	return FuncType;
}

std::unordered_set<func_t*> GetReferenceStaticClassFunctions()
{
	const std::vector<ea_t> EngineStrAddrs = FindWideStringLiteralsByContent("/Script/Engine");
	const std::vector<ea_t> ActorComponentStrAddrs = FindWideStringLiteralsByContent("ActorComponent");
	const std::vector<ea_t> SceneComponentStrAddrs = FindWideStringLiteralsByContent("SceneComponent");
	const std::vector<ea_t> PrimitiveComponentStrAddrs = FindWideStringLiteralsByContent("PrimitiveComponent");
	const std::vector<ea_t> MeshComponentStrAddrs = FindWideStringLiteralsByContent("MeshComponent");

	if (EngineStrAddrs.empty())
	{
		msg("GetReferenceStaticClassFunctions: failed to find L\"/Script/Engine\".\n");
		return {};
	}

	if (ActorComponentStrAddrs.empty() || SceneComponentStrAddrs.empty() || PrimitiveComponentStrAddrs.empty() || MeshComponentStrAddrs.empty())
	{
		msg(
			"GetReferenceStaticClassFunctions: missing one or more reference class strings. "
			"ActorComponent=%d SceneComponent=%d PrimitiveComponent=%d MeshComponent=%d\n",
			static_cast<int>(ActorComponentStrAddrs.size()),
			static_cast<int>(SceneComponentStrAddrs.size()),
			static_cast<int>(PrimitiveComponentStrAddrs.size()),
			static_cast<int>(MeshComponentStrAddrs.size())
		);
	}

	// All refs to L"/Script/Engine", which is used in a lot of StaticClass functions
	std::unordered_set<func_t*>		  EngineStrRefs = GetFunctionsReferencingAnyAddress(EngineStrAddrs);
	const std::unordered_set<func_t*> ActorComponentStrRefs = GetFunctionsReferencingAnyAddress(ActorComponentStrAddrs);
	const std::unordered_set<func_t*> SceneComponentEngineStrRefs = GetFunctionsReferencingAnyAddress(SceneComponentStrAddrs);
	const std::unordered_set<func_t*> PrimitiveComponentStrRefs = GetFunctionsReferencingAnyAddress(PrimitiveComponentStrAddrs);
	const std::unordered_set<func_t*> MeshComponentStrRefs = GetFunctionsReferencingAnyAddress(MeshComponentStrAddrs);

	// Check all references to the strings L"/Script/Engine" and see if they contain L"ActorComponent", L"SceneComponent", etc. to find the StaticClass functions for those classes
	std::erase_if(EngineStrRefs, [&](func_t* RefFunc) -> bool
	{
		return !ActorComponentStrRefs.contains(RefFunc) && !SceneComponentEngineStrRefs.contains(RefFunc) && !PrimitiveComponentStrRefs.contains(RefFunc) && !MeshComponentStrRefs.contains(RefFunc);
	});

	return EngineStrRefs; // At this point EngineStrRefs is a set of only StaticClass functions
}

ea_t GetMostReferencedFunctionInStaticClass()
{
	// Maps a called function to how many StaticClass functions call it
	std::unordered_map<ea_t, uint8_t> ReferencedFunctionAndRefCount;

	for (auto* StaticClassFunc : GetReferenceStaticClassFunctions())
	{
		auto FunctionsCalledByStaticClass = GetCallTargetsInFunc(StaticClassFunc);
		for (auto FunctionCalledByStaticClass : FunctionsCalledByStaticClass)
		{
			ReferencedFunctionAndRefCount[FunctionCalledByStaticClass]++;
		}
	}

	ea_t FuncWithMostReferences = BADADDR;
	int MaxNumRefsEncountered = 0;
	for (auto [ReferencedFunctionAddress, RefCount] : ReferencedFunctionAndRefCount)
	{
		if (RefCount > MaxNumRefsEncountered)
		{
			FuncWithMostReferences = ReferencedFunctionAddress;
			MaxNumRefsEncountered = RefCount;
		}
	}
	return FuncWithMostReferences;
}

bool TestFindStrings()
{
	tinfo_t StaticClassFuncType = BuildStaticClassFuncType();

	ea_t LikelyGetPrivateStaticClassBody = GetMostReferencedFunctionInStaticClass();

	if (LikelyGetPrivateStaticClassBody == BADADDR)
		return false;

	// The shared body every StaticClass() forwards to is UE GetPrivateStaticClassBody
	set_name(LikelyGetPrivateStaticClassBody, "GetPrivateStaticClassBody", SN_NOCHECK | SN_NOWARN | SN_FORCE);

	std::unordered_set<func_t*> AllStaticClassFunctions = GetFunctionsReferencingThisFunction(LikelyGetPrivateStaticClassBody);

	int NumNonInlinedStaticClassCandidates = 0x0;
	int NumNamedStaticClasses = 0x0;
	for (auto* StaticClassFunc : AllStaticClassFunctions)
	{
		const auto FunctionSize = StaticClassFunc->end_ea - StaticClassFunc->start_ea;
		if (FunctionSize < 0x80 || FunctionSize > 0x100)
			continue; // Some StaticClass calls are inlined and therefore substantially bigger than the average 0xB8 bytes

		NumNonInlinedStaticClassCandidates++;

		std::string ObjectName = GetStaticClassNameFromBodyCall(StaticClassFunc, LikelyGetPrivateStaticClassBody);
		if (ObjectName.empty())
		{
			msg("Skipping StaticClassFunc 0x%llX: could not read class name argument.\n", StaticClassFunc->start_ea);
			continue;
		}
		SetStaticClassNameAndSignature(StaticClassFunc, GetPrefixedName(ObjectName), StaticClassFuncType);
		NumNamedStaticClasses++;
	}

	msg("NumStaticClassCandidates: %d\n", NumNonInlinedStaticClassCandidates);
	msg("NumNamedStaticClasses: %d\n", NumNamedStaticClasses);

	return NumNamedStaticClasses > 0;
}

struct IDAMappingsPlugin : public plugmod_t
{
	bool idaapi run(size_t) override
	{
		const auto [PathToDumperGeneratedDirectory, FolderStatus] = AskForSDKFolder("C:\\Dumper-7\\");

		if (FolderStatus == EAvailableFoldersStatus::None)
			return false;

		const bool bCppSDKAvailable      = (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::CppSDK);
		const bool bIDAMappingsAvailable = (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::IDAMappings);

		enum class ETypeSource { Idaclang, Mappings, None };

		qstrvec_t TypeChoices;
		std::vector<ETypeSource> TypeActions;

		if (bCppSDKAvailable)
		{
			TypeChoices.push_back("idaclang (recommended)");
			TypeActions.push_back(ETypeSource::Idaclang);
		}

		if (bIDAMappingsAvailable)
		{
			TypeChoices.push_back("Mappings");
			TypeActions.push_back(ETypeSource::Mappings);
		}

		TypeChoices.push_back("Don't import types");
		TypeActions.push_back(ETypeSource::None);

		static const char TypeSourceForm[] =
			"Import UE types\n"
			"\n"
			"Source for class/struct types (names + functions import either way):\n"
			"\n"
			"  <Type source:b1:0:50::>\n"
			"\n";

		int TypeSel = 0; // default: first (and recommended) available option
		if (ask_form(TypeSourceForm, &TypeChoices, &TypeSel) <= 0)
			return false; // user cancelled

		if (TypeSel < 0 || TypeSel >= static_cast<int>(TypeActions.size()))
			return false;

		const ETypeSource TypeSource = TypeActions[TypeSel];

		// idaclang is only offered when CppSDK is present which parses SDK.hpp for the types
		if (TypeSource == ETypeSource::Idaclang)
		{
			const fs::path SDKHeaderFilePath = PathToDumperGeneratedDirectory / "CppSDK" / "SDK.hpp";

			if (fs::exists(SDKHeaderFilePath))
				ParseSDKHeaderWithClang(SDKHeaderFilePath);
			else
				msg("[IDAMappingsImporter] CppSDK\\SDK.hpp not found.\n");
		}

		// Always import the .idmap when present (names / exec-funcs / globals) and only build types from it in Mappings mode
		if (bIDAMappingsAvailable)
		{
			const fs::path MappingFilePath = FindFileWithExtensionInPath(PathToDumperGeneratedDirectory / "IDAMappings", ".idmap");

			if (!MappingFilePath.empty())
				ReadAndParseIDAMappings(MappingFilePath, TypeSource == ETypeSource::Mappings);
		}

		TestFindStrings();

		return true;
	}
};

static plugmod_t* idaapi init()
{
	return new IDAMappingsPlugin();
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL | PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	"Load .idmap/.usmap mapping files",
	"IDA Mappings Importer - Load UE SDK mapping files",
	"IDA Mappings Importer",
	"Ctrl-Alt-D",
};
