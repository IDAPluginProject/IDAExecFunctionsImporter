#include <Import/MappingsImporter.hpp>
#include <Import/StructBuilder.hpp>
#include <Import/TypeHelpers.hpp>
#include <Import/ExecSignatures.hpp>

#include <Format/Parser.hpp>

static void LoadEnum(const MappingParser& Parser, const IDAMappingsLayouts::Enum& EnumInfo)
{
	const std::string_view EnumName = Parser.GetNameFromOffset(EnumInfo.Name);
	if (EnumName.empty())
		return;

	enum_type_data_t EnumData;
	EnumData.set_nbytes(EnumInfo.UnderlyingTypeSizeBytes);

	for (int i = 0; i < EnumInfo.NumValues; i++)
	{
		const auto ValueName = Parser.GetNameFromOffset(EnumInfo.Values[i].Name);
		if (!ValueName.empty())
			EnumData.push_back(edm_t(std::string(ValueName).c_str(), static_cast<uint64>(EnumInfo.Values[i].Value)));
	}

	tinfo_t Type;

	if (Type.create_enum(EnumData, BTF_ENUM))
		Type.set_named_type(nullptr, std::string(EnumName).c_str(), NTF_TYPE | NTF_REPLACE);
}

static void LoadExecFunction(const MappingParser& Parser, const IDAMappingsLayouts::ExecFunc& Func, ea_t ImageBase, uint32_t Index, bool bHasCppSDKTypes)
{
	const std::string_view Name = Parser.GetNameFromOffset(Func.MangledName);

	if (Name.empty() || Func.OffsetRelativeToImagebase == 0)
		return;

	const ea_t ThunkEA = ImageBase + Func.OffsetRelativeToImagebase;
	set_name(ThunkEA, std::string(Name).c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);

	if (!Parser.HasMinVersion(IDAMappingsLayouts::EIDAMappingsVersion::WithExecSignatures))
		return;
	
	if (bHasCppSDKTypes && Func.CppTypeSignature != static_cast<IDAMappingsLayouts::StringOffset>(-1))
	{
		const std::string_view Signature = Parser.GetNameFromOffset(Func.CppTypeSignature);
		
		if (Signature.empty())
			return;

		tinfo_t FuncType;
		qstring OutName;
		if (parse_decl(&FuncType, &OutName, get_idati(), std::string(Signature).c_str(), PT_SIL | PT_VAR | PT_HIGH | PT_NDC | PT_RELAXED | PT_SEMICOLON))
		{
			if (!apply_tinfo(ThunkEA, FuncType, TINFO_DEFINITE))
			{
				msg("[IDAMappingsImporter] Failed to apply type for %s at 0x%llX\n", std::string(Name).c_str(), static_cast<uint64>(ThunkEA));
				return;
			}
		}
	}
	else
	{
		const IDAMappingsLayouts::StringOffset SignatureOffset = Func.FallbackCppSignatureInfo;
		if (SignatureOffset != static_cast<IDAMappingsLayouts::StringOffset>(-1))
		{
			const std::string_view Signature = Parser.GetNameFromOffset(SignatureOffset);
			if (!Signature.empty())
				RegisterExecSignature(ThunkEA, Signature);
		}
	}
}

static void LoadGlobalSymbol(const MappingParser& Parser, const IDAMappingsLayouts::NamedVariable& Variable, ea_t ImageBase)
{
	using namespace TypeHelpers;

	const std::string_view Name = Parser.GetNameFromOffset(Variable.Name);
	if (Name.empty() || Variable.VariableOffset == 0)
		return;

	const ea_t Addr = ImageBase + Variable.VariableOffset;
	set_name(Addr, std::string(Name).c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);

	const std::string TypeStr(Parser.GetNameFromOffset(Variable.Type));
	if (TypeStr.empty() || TypeStr == "void*")
		return;

	if (TypeStr.back() == '*')
	{
		std::string BaseTypeName = TypeStr.substr(0, TypeStr.size() - 1);
		if (BaseTypeName.starts_with("struct "))
			BaseTypeName = BaseTypeName.substr(7);

		tinfo_t BaseType;
		if (LookupType(BaseTypeName.c_str(), BaseType))
			apply_tinfo(Addr, MakePtrTo(BaseType), TINFO_DEFINITE);
	}
	else
	{
		std::string TypeName = TypeStr;
		if (TypeName.starts_with("struct "))
			TypeName = TypeName.substr(7);

		tinfo_t Type;
		if (LookupType(TypeName.c_str(), Type))
			apply_tinfo(Addr, Type, TINFO_DEFINITE);
	}
}

static void HandleVTableThisPtrRename(MappingParser& Parser, const IDAMappingsLayouts::NamedVTable& VTable, ea_t ImageBase)
{
}

static void ApplyVTableName(MappingParser& Parser, const IDAMappingsLayouts::NamedVTable& VTable, ea_t ImageBase)
{
	if (VTable.VTableOffset == 0)
		return;

	const auto Name = Parser.GetNameFromOffset(VTable.Name);
	if (Name.empty())
		return;

	const ea_t Addr = ImageBase + VTable.VTableOffset;
	set_name(Addr, std::string(Name).c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);
}

static void ImportMappingTypes(MappingParser& Parser)
{
	for (const auto* EnumInfo : Parser.GetAllEnums())
		LoadEnum(Parser, *EnumInfo);

	std::vector<CollectedStruct> Structs;
	std::unordered_map<std::string, size_t> NameMap;

	for (const auto* S : Parser.GetAllStructs())
	{
		CollectedStruct CS;
		CS.Name = std::string(Parser.GetNameFromOffset(S->Name));
		CS.SuperName = (S->SuperName != static_cast<IDAMappingsLayouts::StringOffset>(-1)) ? std::string(Parser.GetNameFromOffset(S->SuperName)) : "";
		CS.FileSize = S->Size;
		CS.Alignment = S->Alignment;
		CS.Raw = S;
		CS.TotalSize = 0;

		if (!CS.Name.empty())
			NameMap[CS.Name] = Structs.size();

		Structs.push_back(std::move(CS));
	}

	bool bRelativeMode = false;
	for (const auto& CS : Structs)
	{
		if (CS.SuperName.empty() || CS.Raw->NumMembers == 0)
			continue;

		auto SuperIt = NameMap.find(CS.SuperName);
		if (SuperIt != NameMap.end() && Structs[SuperIt->second].FileSize <= 0)
			continue;

		for (int i = 0; i < CS.Raw->NumMembers; i++)
		{
			if (CS.Raw->Members[i].Offset == 0)
			{
				bRelativeMode = true;
				break;
			}
		}

		if (bRelativeMode)
			break;
	}

	msg("[IDAMappingsImporter] %s offsets, %zu structs.\n", bRelativeMode ? "Relative" : "Absolute", Structs.size());

	for (size_t i = 0; i < Structs.size(); i++)
		ComputeTotalSize(i, Structs, NameMap, bRelativeMode);

	for (const auto& CS : Structs)
	{
		if (CS.Name.empty() || CS.TotalSize == 0)
			continue;

		ForwardDeclareStruct(CS);
	}

	for (const auto& CS : Structs)
	{
		if (CS.Name.empty() || CS.TotalSize == 0)
			continue;
		PopulateStruct(Parser, CS, Structs, NameMap, bRelativeMode);
	}
}

void LoadMappings(std::vector<uint8_t>&& Buffer, ea_t ImageBase, bool bImportTypes)
{
	MappingParser Parser(std::move(Buffer));

	if (bImportTypes)
		ImportMappingTypes(Parser);

	const bool bHasCppSDKTypes = GHasCppSDKTypes;

	const auto ExecFunctions = Parser.GetAllExecFunctions();
	for (size_t i = 0; i < ExecFunctions.size(); i++)
		LoadExecFunction(Parser, *ExecFunctions[i], ImageBase, static_cast<uint32_t>(i), bHasCppSDKTypes);

	for (const auto* Var : Parser.GetAllGlobalSymbols())
		LoadGlobalSymbol(Parser, *Var, ImageBase);

	for (const auto* VTable : Parser.GetAllNamedVTables())
	{
		const std::string_view Name = Parser.GetNameFromOffset(VTable->Name);
		if (Name.empty() || VTable->VTableOffset == 0)
			continue;

		ApplyVTableName(Parser, *VTable, ImageBase);
		HandleVTableThisPtrRename(Parser, *VTable, ImageBase);
	}
}
