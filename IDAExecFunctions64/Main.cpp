#include <fstream>
#include <stop_token>
#include <vector>
#include <cstring>
#include <Windows.h>
#include <iostream>

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
#include <strlist.hpp>
#include <unordered_set>

#include <Format/Format.hpp>
#include <Import/MappingsImporter.hpp>

#include <filesystem>

namespace fs = std::filesystem;

enum class EAvailableFoldersStatus : uint8_t
{
	None,
	All,
	CppSDK,
	IDAMappings
};

std::pair<fs::path, EAvailableFoldersStatus> AskForSDKFolder(fs::path DefaultPath)
{
	qstring FolderQStr = DefaultPath.string().c_str();

	if (!ask_str(&FolderQStr, HIST_DIR, "Please select a folder containing \"CppSDK\" and \"IDAMappings\" subfolders."))
		return std::pair{ std::string{}, EAvailableFoldersStatus::None};

	fs::path Folder;
	Folder = FolderQStr.c_str();

	fs::path CppSDKPath = Folder / "CppSDK";
	fs::path IDAMappingsPath = Folder / "CppSDK";

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
		return std::pair{ Folder, EAvailableFoldersStatus::CppSDK };
	}

	if (!bhasIDAMappingsFolder)
	{
		warning("Selected folder doesn't contain 'IDAMappings' folder, importing VTables, ExecFunctions and global variables won't be available.");
		return std::pair{ Folder, EAvailableFoldersStatus::IDAMappings };
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

bool IsValidCodePointer(ea_t Address)
{
	segment_t* Seg = getseg(Address);
	if (!Seg)
		return false;

	return Seg->type == SEG_CODE;
}

// Force-define a vtable at the given address, returns number of entries found
int MakeVtable(ea_t Address)
{
	const int PtrSize = inf_is_64bit() ? 8 : 4;
	int EntryCount = 0;

	while (true)
	{
		ea_t EntryAddress = Address + (EntryCount * PtrSize);

		// Read the pointer at this slot
		ea_t FuncPtr = (PtrSize == 8)
			? get_qword(EntryAddress)
			: get_dword(EntryAddress);

		if (!IsValidCodePointer(FuncPtr))
			break;

		// Redefine the slot as a pointer
		del_items(EntryAddress, DELIT_SIMPLE, PtrSize);

		if (PtrSize == 8)
			create_qword(EntryAddress, PtrSize);
		else
			create_dword(EntryAddress, PtrSize);

		// Make sure IDA treats the target as a function
		create_insn(FuncPtr);
		add_func(FuncPtr);

		EntryCount++;
	}

	return EntryCount;
}

struct VtableEntry
{
	ea_t SlotAddress;   // address of the pointer slot in the vtable
	ea_t FuncAddress;   // address of the actual function
	int  Index;
};

static void IterateVtable2(ea_t VtableAddress, std::function<void(const VtableEntry&)> Callback)
{
	const int PtrSize = inf_is_64bit() ? 8 : 4;
	int Index = 0;

	while (true)
	{
		ea_t SlotAddress = VtableAddress + (Index * PtrSize);

		ea_t FuncAddress = (PtrSize == 8)
			? get_qword(SlotAddress)
			: get_dword(SlotAddress);

		if (!IsValidCodePointer(FuncAddress))
			break;

		VtableEntry Entry{ SlotAddress, FuncAddress, Index };
		Callback(Entry);

		Index++;
	}
}
static void IterateVtable(ea_t VtableAddress, std::function<void(const VtableEntry&)> Callback)
{
	const int PtrSize = inf_is_64bit() ? 8 : 4;
	int Index = 0;

	while (true)
	{
		ea_t SlotAddress = VtableAddress + (Index * PtrSize);

		// Stop at the next named item (new vtable, function, data symbol, etc.)
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

void SetunctionThisPtrType(ea_t FuncAddress, tinfo_t ThisType)
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

static void HandleVTableThisPtrRename(ea_t VtableAddress, ea_t SuperVtableAddress, std::string TypeName)
{
	tinfo_t StructType;
	if (!StructType.get_named_type(get_idati(), TypeName.c_str()))
	{
		msg("Failed to find type: %s\n", TypeName.c_str());
		return;
	}

	tinfo_t ThisType;
	ThisType.create_ptr(StructType);

	auto CallSetFunctionThisPtr = [&](const VtableEntry& Entry)
	{
		const ea_t SuperFuncAddressSlot = SuperVtableAddress + Entry.Index * (inf_is_64bit() ? 8 : 4);

		if (SuperVtableAddress && Entry.FuncAddress == get_qword(SuperFuncAddressSlot))
		{
			//qstring SuperVTableName;
			//get_name(&SuperVTableName, SuperVtableAddress);
			//std::cerr << "Super VFT: " << SuperVTableName.c_str() << " Index: 0x" << std::hex << Entry.Index << " matches super vtable, skipping\n";
			//std::cerr << "Skipping vtable entry at 0x" << std::hex << Entry.SlotAddress << " since it matches the super vtable\n";
			return;
		}

		SetunctionThisPtrType(Entry.FuncAddress, ThisType);
	};

	IterateVtable(VtableAddress, CallSetFunctionThisPtr);
}

static void LoadOldMapping(const std::vector<uint8_t>& Buffer, ea_t ImageBase)
{
	size_t Position = 0;
	const size_t Size = Buffer.size();

	while (Position + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) <= Size)
	{
		uint32_t Offset;
		memcpy(&Offset, Buffer.data() + Position, sizeof(Offset));
		Position += sizeof(Offset);
		
		uint32_t SuperOffset;
		memcpy(&SuperOffset, Buffer.data() + Position, sizeof(SuperOffset));
		Position += sizeof(SuperOffset);

		uint16_t NameLength;
		memcpy(&NameLength, Buffer.data() + Position, sizeof(NameLength));
		Position += sizeof(NameLength);

		if (Position + NameLength > Size)
			break;

		std::string Name(reinterpret_cast<const char*>(Buffer.data() + Position), NameLength);
		Position += NameLength;

		set_name(ImageBase + Offset, Name.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);

		static int count = 0;
		if (Name.ends_with("_VFT"))
		{
			msg("Renaming vtable at 0x%llX to %s\n", ImageBase + Offset, Name.c_str());
			HandleVTableThisPtrRename(ImageBase + Offset, ImageBase + SuperOffset, Name.substr(0, Name.length() - 4));
			std::cerr << std::hex << "0x" <<count++ << ": " << Name << "\n";
		}
	}
}

bool ReadAndParseIDAMappings(const fs::path& IDAMappingsFilePath)
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
		LoadMappings(std::move(Buffer), ImageBase);
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

ea_t FindWStrInIDA(const wchar_t* Str, int32_t StrLen)
{
	return bin_search(inf_get_min_ea(), inf_get_max_ea(), (const uchar*)Str, nullptr, StrLen, BIN_SEARCH_FORWARD | BIN_SEARCH_CASE);
}
ea_t FindWStr(const wchar_t* str, int32_t StrLen)
{
	if (!str)
		return BADADDR;

	for (int i = 0; i < get_segm_qty(); i++)
	{
		segment_t* s = getnseg(i);
		if (!s)
			continue;

		// readable, non-writable = typical const data
		if ((s->perm & SEGPERM_WRITE) || !(s->perm & SEGPERM_READ))
			continue;

		qvector<char> f;

		for (int i = 0; i < StrLen; i++)
			f.push_back('x');

		ea_t found = bin_search(
			s->start_ea,
			s->end_ea,
			(const uchar*)str,
			(const uchar*)f.begin(),
			StrLen,
			BIN_SEARCH_FORWARD
		);

		if (found == BADADDR)
			break;

		return found; // exact full-string match (incl null)
	}

	return BADADDR;
}
ea_t FindWStr2(const char* Str)
{
	string_info_t Si;
	for (size_t i = 0; i < get_strlist_qty(); i++)
	{
		get_strlist_item(&Si, i);

		if (Si.type != STRTYPE_C_16)
			continue;

		qstring Content;
		get_strlit_contents(&Content, Si.ea, Si.length, Si.type);

		std::cerr << Content.c_str() << "\n";
		if (Content.c_str() == Str)
			return Si.ea;
	}

	return BADADDR;
}

std::vector<ea_t> GetXRefs(const ea_t Address)
{
	std::vector<ea_t> Ret;

	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(Address, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		msg("Xref from 0x%llx, type: %d\n", Xref.from, Xref.type);
		Ret.push_back(Xref.from);
	}

	return Ret;
}

std::unordered_set<func_t*> GetFunctionsReferencingThisFunction(const ea_t Address)
{
	std::unordered_set<func_t*> Ret;

	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(Address, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		msg("Xref from 0x%llx, type: %d\n", Xref.from, Xref.type);
		if (func_t* Function = get_func(Xref.from))
			Ret.insert(Function);
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

// Collect all wide-string (UTF-16LE) xrefs from inside a function, ordered by
// the address of the referencing instruction (i.e. order of appearance).
static std::vector<std::wstring> GetWideStringRefsInFunc(func_t* Func)
{
	std::vector<std::pair<ea_t, std::wstring>> Refs;

	for (ea_t Addr = Func->start_ea; Addr < Func->end_ea; Addr = next_head(Addr, Func->end_ea))
	{
		if (!is_code(get_flags(Addr)))
			continue;

		insn_t Insn;
		if (decode_insn(&Insn, Addr) <= 0)
			continue;

		// Look at every operand for a data reference to a wide string.
		for (int OpIdx = 0; OpIdx < UA_MAXOP; ++OpIdx)
		{
			const op_t& Op = Insn.ops[OpIdx];
			if (Op.type == o_void)
				break;

			ea_t TargetEa = BADADDR;
			if (Op.type == o_mem || Op.type == o_near || Op.type == o_far)
				TargetEa = Op.addr;
			else if (Op.type == o_imm)
				TargetEa = static_cast<ea_t>(Op.value);

			if (TargetEa == BADADDR)
				continue;

			// Read up to 512 wchars; bail if first word is not a printable ASCII range.
			const uint16 FirstWord = get_word(TargetEa);
			if (FirstWord < 0x20 || FirstWord > 0x7E)
				continue;

			std::wstring Str;
			for (int CharIdx = 0; CharIdx < 512; ++CharIdx)
			{
				const uint16 Ch = get_word(TargetEa + CharIdx * 2);
				if (Ch == 0)
					break;
				if (Ch > 0x7E) // non-ASCII wide char — probably not our string
				{
					Str.clear();
					break;
				}
				Str.push_back(static_cast<wchar_t>(Ch));
			}

			if (!Str.empty())
				Refs.push_back({ Addr, std::move(Str) });
		}
	}

	// Sort by referencing instruction address so we get them in code order.
	std::sort(Refs.begin(), Refs.end(), [](const auto& A, const auto& B)
	{
		return A.first < B.first;
	});

	// Deduplicate consecutive identical refs (same lea reused).
	std::vector<std::wstring> Result;
	for (auto& [Addr, Str] : Refs)
	{
		if (Result.empty() || Result.back() != Str)
			Result.push_back(std::move(Str));
	}

	return Result;
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

void PrintArgLocation(const funcarg_t& Arg)
{
	const argloc_t& Loc = Arg.argloc;

	if (Loc.is_reg())
	{
		qstring RegName;
		get_reg_name(&RegName, Loc.reg1(), Arg.type.get_size());
		msg("Arg '%s' is in register: %s\n", Arg.name.c_str(), RegName.c_str());
	}
	else if (Loc.is_stkoff())
	{
		msg("Arg '%s' is at stack offset: %d\n",
			Arg.name.c_str(),
			Loc.stkoff());
	}
	else if (Loc.is_scattered())
	{
		msg("Arg '%s' is scattered across multiple locations\n", Arg.name.c_str());
	}
}


void DumpFuncArgs(ea_t FuncAddr)
{
	tinfo_t FuncTinfo;
	if (!get_tinfo(&FuncTinfo, FuncAddr))
	{
		msg("No type info for 0x%llx\n", (uint64)FuncAddr);
		return;
	}

	func_type_data_t FuncData;
	if (!FuncTinfo.get_func_details(&FuncData))
	{
		msg("Failed to get func details\n");
		return;
	}

	msg("Function has %d args:\n", (int)FuncData.size());

	for (int i = 0; i < (int)FuncData.size(); ++i)
	{
		const funcarg_t& Arg = FuncData[i];

		qstring TypeStr;
		Arg.type.print(&TypeStr);

		msg("  [%d] %s %s\n", i, TypeStr.c_str(), Arg.name.c_str());
		PrintArgLocation(Arg);
	}
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
		// Fallback to void* if the type isn't present to avoid an invalid signature.
		UClassType.create_typedef(get_idati(), "void");
	}

	// Convert UClass to UClass*
	UClassType.create_ptr(UClassType);

	// Prepare the function prototype data.
	func_type_data_t FuncData;
	FuncData.rettype = UClassType;
	FuncData.clear();            // Ensure no arguments are defined.

	// Create the final function tinfo_t.
	tinfo_t FuncType;
	if (!FuncType.create_func(FuncData))
	{
		msg("Error: Failed to create function signature object.\n");
	}

	return FuncType;
}

/**
 * Converts a tinfo_t to a human-readable std::string.
 */
std::string GetTypeString(const tinfo_t& InType)
{
	qstring TypeName;
	if (InType.print(&TypeName))
	{
		return std::string(TypeName.c_str());
	}

	return std::string("UnknownType");
}

std::unordered_set<func_t*> GetReferenceStaticClassFunctions()
{
	ea_t EngineStrAddr = 0x7D89B00;
	ea_t ActorComponentStrAddr = 0x8678290;
	ea_t SceneComponentStrAddr = 0x8569F10;
	ea_t PrimitiveComponentStrAddr = 0x85B9360;
	ea_t MeshComponentStrAddr = 0x086A8330;

	// All refs to L"/Script/Engine", which is used in a lot of StaticClass functions
	std::unordered_set<func_t*>		  EngineStrRefs = GetFunctionsReferencingThisFunction(EngineStrAddr);
	const std::unordered_set<func_t*> ActorComponentStrRefs = GetFunctionsReferencingThisFunction(ActorComponentStrAddr);
	const std::unordered_set<func_t*> SceneComponentEngineStrRefs = GetFunctionsReferencingThisFunction(SceneComponentStrAddr);
	const std::unordered_set<func_t*> PrimitiveComponentStrRefs = GetFunctionsReferencingThisFunction(PrimitiveComponentStrAddr);
	const std::unordered_set<func_t*> MeshComponentStrRefs = GetFunctionsReferencingThisFunction(MeshComponentStrAddr);

	// Check all references to the strings L"/Script/Engine" and see if they contain L"ActorComponent", L"SceneComponent", etc. to find the StaticClass functions for those classes
	std::erase_if(EngineStrRefs, [&](func_t* RefFunc) -> bool
	{
		return !ActorComponentStrRefs.contains(RefFunc) && !SceneComponentEngineStrRefs.contains(RefFunc) && !PrimitiveComponentStrRefs.contains(RefFunc) && !MeshComponentStrRefs.contains(RefFunc);
	});

	return EngineStrRefs; // At this point EngineStrRefs is a set of only StaticClass functions
}

ea_t GetMostRefrencedFunctionInStaticClass()
{
	// Vector<Pair<FunctionReferencedByStaticClass, NumReverencesEncountered>
	std::unordered_map<ea_t, uint8_t> ReferencedFunctionAndRefCount;

	for (auto* StaticClassFunc : GetReferenceStaticClassFunctions())
	{
		std::cerr << "StaticClassFunc: 0x" << StaticClassFunc->start_ea << "\n";
		msg("StaticClassFunc: 0x%llX\n", StaticClassFunc->start_ea);

		auto FunctionsCalledByStaticClass = GetCallTargetsInFunc(StaticClassFunc);
		for (auto FunctionCalledByStaticClass : FunctionsCalledByStaticClass)
		{
			std::cout << "FunctionCalledByStaticClass: " << FunctionCalledByStaticClass << "\n";
			msg("FunctionCalledByStaticClass: %llX\n", FunctionCalledByStaticClass);

			ReferencedFunctionAndRefCount[FunctionCalledByStaticClass]++;
		}
	}

	ea_t FuncWithMostReferences = NULL;
	int MaxNumRefsEncoutnered = 0;
	for (auto [ReferencedFunctionAddress, RefCount] : ReferencedFunctionAndRefCount)
	{
		if (RefCount > MaxNumRefsEncoutnered)
		{
			FuncWithMostReferences = ReferencedFunctionAddress;
			MaxNumRefsEncoutnered = RefCount;
		}
	}
	return FuncWithMostReferences;
}

bool TestFindStrings()
{
	constexpr const wchar_t* EngineStr = L"/Script/Engine";

	constexpr const wchar_t* ActorComponentStr = L"ActorComponent";
	constexpr const wchar_t* SceneComponentStr = L"SceneComponent";
	constexpr const wchar_t* PrimitiveComponentStr = L"PrimitiveComponent";
	constexpr const wchar_t* MeshComponentStr = L"MeshComponent";

	bool bCanTypeReturnValueToUClass = true;
	tinfo_t StructType;
	if (!StructType.get_named_type(get_idati(), "UClass")) // Creates type if doesn't exist
	{
		msg("Failed to find/create type UClass\n");
		bCanTypeReturnValueToUClass = false;
	}

	tinfo_t StaticClassFuncType = BuildStaticClassFuncType();

	tinfo_t FuncPtrType;
	qstring Name;
	parse_decl(&FuncPtrType, &Name, get_idati(), "UClass*(*)()", PT_SIL);

	ea_t LikelyGetPrivateStaticClassBody = GetMostRefrencedFunctionInStaticClass();

	if (!LikelyGetPrivateStaticClassBody)
		return false; 

	std::unordered_set<func_t*> AllStaticClassFunctions = GetFunctionsReferencingThisFunction(LikelyGetPrivateStaticClassBody);

	int count = 0;
	int NumValidStaticClassCalls = 0x0;
	for (auto* StaticClassFunc : AllStaticClassFunctions)
	{
		//if (count++ > 100)
		//	break;

		const auto FunctionSize = StaticClassFunc->end_ea - StaticClassFunc->start_ea;
		if (FunctionSize < 0x80 || FunctionSize > 0x100)
			continue; // Some StaticClass calls are inlined and therefore substantially bigger than the average 0xB8 bytes

		NumValidStaticClassCalls++;

		std::cerr << "StaticClassFunc: 0x" << StaticClassFunc->start_ea << "\n";
		msg("StaticClassFunc: 0x%llX\n", StaticClassFunc->start_ea);

		auto WStrRefs = GetWideStringRefsInFunc(StaticClassFunc);
		//for (auto& WStrRef : WStrRefs)
		//{
		//	std::string TargetStr = WStrToStr(WStrRef);
		//	std::cout << "WStrRef: " << TargetStr << "\n";
		//	msg("WStrRef: %s\n", TargetStr.c_str());
		//}
		if (WStrRefs.size() > 1)
		{
			std::string TargetStr = WStrToStr(WStrRefs[1]);
			std::cerr << "WStrRef: " << TargetStr << "\n";
			msg("WStrRef: %s\n", TargetStr.c_str());
		}

		SetStaticClassNameAndSignature(StaticClassFunc, GetPrefixedName(WStrToStr(WStrRefs[1])), StaticClassFuncType);
	}

	std::cerr << "NumStaticClasses: " << NumValidStaticClassCalls << "\n";
	msg("NumStaticClasses: %llX\n", NumValidStaticClassCalls);

	//std::vector<ea_t> AllStaticClassFunctions2 = GetXRefs(LikelyGetPrivateStaticClassBody);
	//
	//// [7] = CastFlags
	//DumpFuncArgs(LikelyGetPrivateStaticClassBody);
}

struct IDAMappingsPlugin : public plugmod_t
{
	bool idaapi run(size_t) override
	{
		AllocConsole();
		FILE* Dummy;
		freopen_s(&Dummy, "CONOUT$", "w", stderr);
		freopen_s(&Dummy, "CONIN$", "r", stdin);

		const auto&& [PathToDumperGeneratedDirectory, FolderStatus] = AskForSDKFolder("C:\\Dumper-7\\5.6.0-0+UE5-TheIsle");

		if (FolderStatus == EAvailableFoldersStatus::None)
			return false;

		if (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::IDAMappings)
		{
			const fs::path MappingFilePath = FindFileWithExtensionInPath(PathToDumperGeneratedDirectory / "IDAMappings", ".idmap");
		
			if (!MappingFilePath.empty())
				ReadAndParseIDAMappings(MappingFilePath);
		}
		if (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::IDAMappings)
		{
			const fs::path SDKHeaderFilePath = PathToDumperGeneratedDirectory / "CppSDK" / "SDK.hpp";
		
			if (fs::exists(SDKHeaderFilePath))
				ParseSDKHeaderWithClang(SDKHeaderFilePath);
		}

		std::cerr << "Teststart:" << std::endl;

		auto DumpStartTime = std::chrono::high_resolution_clock::now();
		const bool bIsTrue = TestFindStrings();
		auto DumpFinishTime = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> DumpTime = DumpFinishTime - DumpStartTime;

		std::cerr << "\n\nLoading Files took (" << DumpTime.count() << "ms)\n\n\n";
		std::cerr << "TestResult: " << (int)bIsTrue << std::endl;


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
	"IDAMappingsImporteor",
	"Ctrl-Alt-D",
};
