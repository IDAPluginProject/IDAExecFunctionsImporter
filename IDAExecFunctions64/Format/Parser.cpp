#include <Format/Parser.hpp>

#include <format>
#include <iostream>

std::string_view MappingParser::GetNameFromOffset(const IDAMappingsLayouts::OffsetType NameOffset) const
{
	const auto* Header = GetHeader();
	if (!Header)
		return std::string_view{};

	if (NameOffset > Header->StringDataSizeBytes)
		return std::string_view{};

	const size_t StringStart = static_cast<size_t>(Header->StringDataOffset) + NameOffset;
	const auto* String = GetDataAtOffset<IDAMappingsLayouts::StringData>(StringStart);
	if (!String)
		return std::string_view{};

	// Compute the end in size_t so a crafted length can't wrap past the bounds checks
	const size_t LastAccessedByteOffset = static_cast<size_t>(NameOffset) + sizeof(String->StringLength) + String->StringLength;

	if (LastAccessedByteOffset > Header->StringDataSizeBytes || !CanReadData(StringStart + sizeof(IDAMappingsLayouts::StringData::StringLength), String->StringLength))
		return std::string_view{};

	return std::string_view(String->Utf8StringData, String->StringLength);
}

const IDAMappingsLayouts::Struct* MappingParser::ParseSingleStruct(const IDAMappingsLayouts::OffsetType CurrentStructStart, IDAMappingsLayouts::OffsetType& OutStructDataEnd)
{
	const auto* StructInfo = GetDataAtOffset<IDAMappingsLayouts::Struct>(CurrentStructStart);
	if (!StructInfo)
		return nullptr;

	if (StructInfo->NumMembers < 0)
		return nullptr;

	const auto StructMemberStart = CurrentStructStart + offsetof(IDAMappingsLayouts::Struct, Members);
	const auto StructMemberSizeBytes = sizeof(IDAMappingsLayouts::Member) * static_cast<size_t>(StructInfo->NumMembers);

	if (!CanReadData(StructMemberStart, StructMemberSizeBytes))
		return nullptr;

	OutStructDataEnd = static_cast<IDAMappingsLayouts::OffsetType>(StructMemberStart + StructMemberSizeBytes);
	return StructInfo;
}

const IDAMappingsLayouts::Enum* MappingParser::ParseSingleEnum(const IDAMappingsLayouts::OffsetType CurrentEnumStart, IDAMappingsLayouts::OffsetType& OutEnumDataEnd)
{
	const auto* EnumInfo = GetDataAtOffset<IDAMappingsLayouts::Enum>(CurrentEnumStart);
	if (!EnumInfo)
		return nullptr;

	if (EnumInfo->NumValues < 0)
		return nullptr;

	const auto EnumValuesStart = CurrentEnumStart + offsetof(IDAMappingsLayouts::Enum, Values);
	const auto EnumValuesSizeBytes = sizeof(IDAMappingsLayouts::EnumValue) * static_cast<size_t>(EnumInfo->NumValues);

	if (!CanReadData(EnumValuesStart, EnumValuesSizeBytes))
		return nullptr;

	OutEnumDataEnd = static_cast<IDAMappingsLayouts::OffsetType>(EnumValuesStart + EnumValuesSizeBytes);
	return EnumInfo;
}

bool MappingParser::IsValidHeader() const
{
	const auto* Header = GetHeader();
	if (!Header)
		return false;

	if (Header->Magic != IDAMappingsLayouts::FileMagic)
		return false;

	if (Header->Version < IDAMappingsLayouts::EIDAMappingsVersion::WithExecSignatures)
		return false;

	if (!CanReadData(Header->StringDataOffset, Header->StringDataSizeBytes))
		return false;

	if (Header->Version > IDAMappingsLayouts::EIDAMappingsVersion::WithExecSignatures
		&& !CanReadData(0, sizeof(IDAMappingsLayouts::IDAMappingsHeader)))
	{
		return false;
	}

	return CanReadData(Header->StructDataOffset, 0)
		&& CanReadData(Header->EnumDataOffset, 0)
		&& CanReadData(Header->GlobalSymbolDataOffset, 0)
		&& CanReadData(Header->ExecFunctionDataOffset, 0);
}

std::vector<const IDAMappingsLayouts::Struct*> MappingParser::GetAllStructs()
{
	std::vector<const IDAMappingsLayouts::Struct*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	IDAMappingsLayouts::OffsetType CurrentOffset = Header->StructDataOffset;

	for (uint32_t i = 0; i < Header->NumStructs; i++)
	{
		const auto* StructInfo = ParseSingleStruct(CurrentOffset, CurrentOffset);
		if (!StructInfo)
			break;

		Result.push_back(StructInfo);
	}

	return Result;
}

std::vector<const IDAMappingsLayouts::Enum*> MappingParser::GetAllEnums()
{
	std::vector<const IDAMappingsLayouts::Enum*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	IDAMappingsLayouts::OffsetType CurrentOffset = Header->EnumDataOffset;

	for (uint32_t i = 0; i < Header->NumEnums; i++)
	{
		const auto* EnumInfo = ParseSingleEnum(CurrentOffset, CurrentOffset);
		if (!EnumInfo)
			break;

		Result.push_back(EnumInfo);
	}

	return Result;
}

std::vector<const IDAMappingsLayouts::ExecFunc*> MappingParser::GetAllExecFunctions()
{
	std::vector<const IDAMappingsLayouts::ExecFunc*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	for (uint32_t i = 0; i < Header->NumExecFunctions; i++)
	{
		const auto Offset = Header->ExecFunctionDataOffset + (i * sizeof(IDAMappingsLayouts::ExecFunc));
		const auto* Func = GetDataAtOffset<IDAMappingsLayouts::ExecFunc>(Offset);

		if (!Func)
			break;

		Result.push_back(Func);
	}

	return Result;
}

std::vector<const IDAMappingsLayouts::NamedVTable*> MappingParser::GetAllNamedVTables()
{
	std::vector<const IDAMappingsLayouts::NamedVTable*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	for (uint32_t i = 0; i < Header->NumVTables; i++)
	{
		const auto Offset = Header->VTableDataOffset + (i * sizeof(IDAMappingsLayouts::NamedVTable));
		const auto* VTable = GetDataAtOffset<IDAMappingsLayouts::NamedVTable>(Offset);

		if (!VTable)
			break;

		Result.push_back(VTable);
	}

	return Result;
}

//IDAMappingsLayouts::StringOffset MappingParser::GetExecFuncSignatureOffset(uint32_t Index) const
//{
//	const auto* Header = GetHeader();
//	if (!Header)
//		return static_cast<IDAMappingsLayouts::StringOffset>(-1);
//
//	if (Header->Version < IDAMappingsLayouts::EIDAMappingsVersion::WithExecSignatures)
//		return static_cast<IDAMappingsLayouts::StringOffset>(-1);
//
//	// GetHeader only guaranteed the v1 fields; ensure the appended v2 field is in bounds too
//	if (!CanReadData(0, sizeof(IDAMappingsLayouts::IDAMappingsHeader)))
//		return static_cast<IDAMappingsLayouts::StringOffset>(-1);
//
//	if (Index >= Header->NumExecFunctions)
//		return static_cast<IDAMappingsLayouts::StringOffset>(-1);
//
//	const auto Offset = Header->ExecFuncSignatureDataOffset + (Index * sizeof(IDAMappingsLayouts::StringOffset));
//	const auto* SignatureOffset = GetDataAtOffset<IDAMappingsLayouts::StringOffset>(Offset);
//
//	return SignatureOffset ? *SignatureOffset : static_cast<IDAMappingsLayouts::StringOffset>(-1);
//}

std::vector<const IDAMappingsLayouts::NamedVariable*> MappingParser::GetAllGlobalSymbols()
{
	std::vector<const IDAMappingsLayouts::NamedVariable*> Result;

	const auto* Header = GetHeader();
	if (!Header)
		return Result;

	for (uint32_t i = 0; i < Header->NumGlobalSymbols; i++)
	{
		const auto Offset = Header->GlobalSymbolDataOffset + (i * sizeof(IDAMappingsLayouts::NamedVariable));
		const auto* Var = GetDataAtOffset<IDAMappingsLayouts::NamedVariable>(Offset);

		if (!Var)
			break;

		Result.push_back(Var);
	}

	return Result;
}
