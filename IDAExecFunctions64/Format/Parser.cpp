#include <Format/Parser.hpp>

#include <format>
#include <iostream>

std::string_view MappingParser::GetNameFromOffset(const MappingLayouts::OffsetType NameOffset) const
{
	const auto* Header = GetHeader();
	if (!Header)
		return std::string_view{};

	if (NameOffset > Header->StringDataSizeBytes)
		return std::string_view{};

	const size_t StringStart = static_cast<size_t>(Header->StringDataOffset) + NameOffset;
	const auto* String = GetDataAtOffset<MappingLayouts::StringData>(StringStart);
	if (!String)
		return std::string_view{};

	// Compute the end in size_t so a crafted length can't wrap past the bounds checks
	const size_t LastAccessedByteOffset = static_cast<size_t>(NameOffset) + sizeof(String->StringLength) + String->StringLength;

	if (LastAccessedByteOffset > Header->StringDataSizeBytes || !CanReadData(StringStart + sizeof(MappingLayouts::StringData::StringLength), String->StringLength))
		return std::string_view{};

	return std::string_view(String->Utf8StringData, String->StringLength);
}

const MappingLayouts::Struct* MappingParser::ParseSingleStruct(const MappingLayouts::OffsetType CurrentStructStart, MappingLayouts::OffsetType& OutStructDataEnd)
{
	const auto* StructInfo = GetDataAtOffset<MappingLayouts::Struct>(CurrentStructStart);
	if (!StructInfo)
		return nullptr;

	if (StructInfo->NumMembers < 0)
		return nullptr;

	const auto StructMemberStart = CurrentStructStart + offsetof(MappingLayouts::Struct, Members);
	const auto StructMemberSizeBytes = sizeof(MappingLayouts::Member) * static_cast<size_t>(StructInfo->NumMembers);

	if (!CanReadData(StructMemberStart, StructMemberSizeBytes))
		return nullptr;

	OutStructDataEnd = static_cast<MappingLayouts::OffsetType>(StructMemberStart + StructMemberSizeBytes);
	return StructInfo;
}

const MappingLayouts::Enum* MappingParser::ParseSingleEnum(const MappingLayouts::OffsetType CurrentEnumStart, MappingLayouts::OffsetType& OutEnumDataEnd)
{
	const auto* EnumInfo = GetDataAtOffset<MappingLayouts::Enum>(CurrentEnumStart);
	if (!EnumInfo)
		return nullptr;

	if (EnumInfo->NumValues < 0)
		return nullptr;

	const auto EnumValuesStart = CurrentEnumStart + offsetof(MappingLayouts::Enum, Values);
	const auto EnumValuesSizeBytes = sizeof(MappingLayouts::EnumValue) * static_cast<size_t>(EnumInfo->NumValues);

	if (!CanReadData(EnumValuesStart, EnumValuesSizeBytes))
		return nullptr;

	OutEnumDataEnd = static_cast<MappingLayouts::OffsetType>(EnumValuesStart + EnumValuesSizeBytes);
	return EnumInfo;
}

bool MappingParser::IsValidHeader() const
{
	const auto* Header = GetHeader();
	if (!Header)
		return false;

	if (Header->Magic != MappingLayouts::FileMagic)
		return false;

	if (Header->Version != MappingLayouts::EIDAMappingsVersion::Initial
		&& Header->Version != MappingLayouts::EIDAMappingsVersion::WithExecSignatures)
		return false;

	if (!CanReadData(Header->StringDataOffset, Header->StringDataSizeBytes))
		return false;

	return CanReadData(Header->StructDataOffset, 0)
		&& CanReadData(Header->EnumDataOffset, 0)
		&& CanReadData(Header->GlobalSymbolDataOffset, 0)
		&& CanReadData(Header->ExecFunctionDataOffset, 0);
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

MappingLayouts::StringOffset MappingParser::GetExecFuncSignatureOffset(uint32_t Index) const
{
	const auto* Header = GetHeader();
	if (!Header)
		return static_cast<MappingLayouts::StringOffset>(-1);

	if (Header->Version < MappingLayouts::EIDAMappingsVersion::WithExecSignatures)
		return static_cast<MappingLayouts::StringOffset>(-1);

	// GetHeader only guaranteed the v1 fields; ensure the appended v2 field is in bounds too
	if (!CanReadData(0, sizeof(MappingLayouts::IDAMappingsHeader)))
		return static_cast<MappingLayouts::StringOffset>(-1);

	if (Index >= Header->NumExecFunctions)
		return static_cast<MappingLayouts::StringOffset>(-1);

	const auto Offset = Header->ExecFuncSignatureDataOffset + (Index * sizeof(MappingLayouts::StringOffset));
	const auto* SignatureOffset = GetDataAtOffset<MappingLayouts::StringOffset>(Offset);

	return SignatureOffset ? *SignatureOffset : static_cast<MappingLayouts::StringOffset>(-1);
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
