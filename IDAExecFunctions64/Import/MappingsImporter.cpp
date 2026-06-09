#include <Import/MappingsImporter.hpp>
#include <Import/StructBuilder.hpp>
#include <Import/TypeHelpers.hpp>

#include <Format/Parser.hpp>

static void LoadEnum(const MappingParser& Parser, const MappingLayouts::Enum& EnumInfo)
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

static void LoadExecFunction(const MappingParser& Parser, const MappingLayouts::ExecFunc& Func, ea_t ImageBase)
{
	const std::string_view Name = Parser.GetNameFromOffset(Func.MangledName);

	if (!Name.empty() && Func.OffsetRelativeToImagebase != 0)
		set_name(ImageBase + Func.OffsetRelativeToImagebase, std::string(Name).c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);
}

static void LoadGlobalSymbol(const MappingParser& Parser, const MappingLayouts::NamedVariable& Variable, ea_t ImageBase)
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
		CS.SuperName = (S->SuperName != static_cast<MappingLayouts::StringOffset>(-1)) ? std::string(Parser.GetNameFromOffset(S->SuperName)) : "";
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

	for (const auto* Func : Parser.GetAllExecFunctions())
		LoadExecFunction(Parser, *Func, ImageBase);

	for (const auto* Var : Parser.GetAllGlobalSymbols())
		LoadGlobalSymbol(Parser, *Var, ImageBase);
}
