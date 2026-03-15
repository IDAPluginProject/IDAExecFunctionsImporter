#include <Format/Parser.hpp>

#include <format>
#include <iostream>

std::string_view MappingParser::GetNameFromOffset(const MappingLayouts::OffsetType NameOffset) const
{
	const auto* Header = GetHeader();
	if (!Header)
		return std::string_view{};

	const auto* String = GetDataAtOffset<MappingLayouts::StringData>(Header->StringDataOffset + NameOffset);
	if (!String)
		return std::string_view{};

	const uint32_t LastAccessedByteOffset = NameOffset + sizeof(String->StringLength) + String->StringLength;

	if (LastAccessedByteOffset > Header->StringDataSizeBytes || !CanReadData(Header->StringDataOffset + NameOffset + sizeof(MappingLayouts::StringData::StringLength), String->StringLength))
		return std::string_view{};

	return std::string_view(String->Utf8StringData, String->StringLength);
}

const MappingLayouts::Struct* MappingParser::ParseSingleStruct(const MappingLayouts::OffsetType CurrentStructStart, MappingLayouts::OffsetType& OutStructDataEnd)
{
	const auto* StructInfo = GetDataAtOffset<MappingLayouts::Struct>(CurrentStructStart);
	if (!StructInfo)
		return nullptr;

	const auto StructMemberStart = CurrentStructStart + offsetof(MappingLayouts::Struct, Members);
	const auto StructMemberSizeBytes = sizeof(MappingLayouts::Member) * StructInfo->NumMembers;

	if (!CanReadData(StructMemberStart, StructMemberSizeBytes))
		return nullptr;

	OutStructDataEnd = StructMemberStart + StructMemberSizeBytes;
	return StructInfo;
}

const MappingLayouts::Enum* MappingParser::ParseSingleEnum(const MappingLayouts::OffsetType CurrentEnumStart, MappingLayouts::OffsetType& OutEnumDataEnd)
{
	const auto* EnumInfo = GetDataAtOffset<MappingLayouts::Enum>(CurrentEnumStart);
	if (!EnumInfo)
		return nullptr;

	const auto EnumValuesStart = CurrentEnumStart + offsetof(MappingLayouts::Enum, Values);
	const auto EnumValuesSizeBytes = sizeof(MappingLayouts::EnumValue) * EnumInfo->NumValues;

	if (!CanReadData(EnumValuesStart, EnumValuesSizeBytes))
		return nullptr;

	OutEnumDataEnd = EnumValuesStart + EnumValuesSizeBytes;
	return EnumInfo;
}

std::vector<const MappingLayouts::Struct*> MappingParser::GetAllStructs()
{
	std::vector<const MappingLayouts::Struct*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	MappingLayouts::OffsetType CurrentOffset = Header->StructDataOffset;

	for (uint32_t i = 0; i < Header->NumStructs; i++)
	{
		const auto* StructInfo = ParseSingleStruct(CurrentOffset, CurrentOffset);
		if (!StructInfo)
			break;

		Result.push_back(StructInfo);
	}

	return Result;
}

std::vector<const MappingLayouts::Enum*> MappingParser::GetAllEnums()
{
	std::vector<const MappingLayouts::Enum*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	MappingLayouts::OffsetType CurrentOffset = Header->EnumDataOffset;

	for (uint32_t i = 0; i < Header->NumEnums; i++)
	{
		const auto* EnumInfo = ParseSingleEnum(CurrentOffset, CurrentOffset);
		if (!EnumInfo)
			break;

		Result.push_back(EnumInfo);
	}

	return Result;
}

std::vector<const MappingLayouts::ExecFunc*> MappingParser::GetAllExecFunctions()
{
	std::vector<const MappingLayouts::ExecFunc*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	for (uint32_t i = 0; i < Header->NumExecFunctions; i++)
	{
		const auto Offset = Header->ExecFunctionDataOffset + (i * sizeof(MappingLayouts::ExecFunc));
		const auto* Func = GetDataAtOffset<MappingLayouts::ExecFunc>(Offset);

		if (!Func)
			break;

		Result.push_back(Func);
	}

	return Result;
}

std::vector<const MappingLayouts::NamedVariable*> MappingParser::GetAllGlobalSymbols()
{
	std::vector<const MappingLayouts::NamedVariable*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	for (uint32_t i = 0; i < Header->NumGlobalSymbols; i++)
	{
		const auto Offset = Header->GlobalSymbolDataOffset + (i * sizeof(MappingLayouts::NamedVariable));
		const auto* Var = GetDataAtOffset<MappingLayouts::NamedVariable>(Offset);

		if (!Var)
			break;

		Result.push_back(Var);
	}

	return Result;
}
