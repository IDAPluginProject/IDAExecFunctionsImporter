#include "IDAMappingsParser.h"

#include <format>
#include <iostream>

std::string_view IDAMappingsParser::GetNameFromOffset(const IDAMappingsLayouts::StringOffset NameOffset) const
{
	if (NameOffset < 0x0)
		return std::string_view{};

	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return std::string_view{};

	const IDAMappingsLayouts::StringData* Str = GetDataAtOffset<IDAMappingsLayouts::StringData>(Header->StringDataOffset + NameOffset);
	if (!Str)
		return std::string_view{};

	const uint32_t LastAccessedByteOffset = NameOffset + sizeof(Str->StrLenth) + Str->StrLenth;

	if (LastAccessedByteOffset >= Header->StringDataSizeBytes || !CanReadData(NameOffset + sizeof(IDAMappingsLayouts::StringData::StrLenth), Str->StrLenth))
		return std::string_view{};

	return std::string_view(Str->Utf8StrData, Str->StrLenth);
}


const IDAMappingsLayouts::Struct* IDAMappingsParser::ParseSingleStruct(const IDAMappingsLayouts::OffsetType CurrentStructStart, IDAMappingsLayouts::OffsetType& OutStructDataEnd)
{
	const IDAMappingsLayouts::Struct* StructInfo = GetDataAtOffset<IDAMappingsLayouts::Struct>(CurrentStructStart);

	if (!StructInfo)
		return nullptr;

	const auto StructMemberStart = CurrentStructStart + offsetof(IDAMappingsLayouts::Struct, Members);
	const auto StructMemberSizeBytes = sizeof(IDAMappingsLayouts::Member) * StructInfo->NumMembers;

	if (!CanReadData(StructMemberStart, StructMemberSizeBytes))
		return nullptr;

	OutStructDataEnd = StructMemberStart + StructMemberSizeBytes;

	return StructInfo;
}

void IDAMappingsParser::ParseAllStructsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::Struct&)> Callback)
{
	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return;

	IDAMappingsLayouts::OffsetType CurrentOffset = Header->StructDataOffset;

	for (uint32_t i = 0; i < Header->NumStructs; i++)
	{
		// ParseSingleStruct updates CurrentOffset to point to the next struct
		const IDAMappingsLayouts::Struct* StructInfo = ParseSingleStruct(CurrentOffset, CurrentOffset);

		if (!StructInfo)
			break;

		Callback(*this, *StructInfo);
	}
}


const IDAMappingsLayouts::Enum* IDAMappingsParser::ParseSingleEnum(const IDAMappingsLayouts::OffsetType CurrentEnumStart, IDAMappingsLayouts::OffsetType& OuEnumDataEnd)
{
	const IDAMappingsLayouts::Enum* EnumInfo = GetDataAtOffset<IDAMappingsLayouts::Enum>(CurrentEnumStart);

	if (!EnumInfo)
		return nullptr;

	const auto EnumValuesStart = CurrentEnumStart + offsetof(IDAMappingsLayouts::Enum, Values);
	const auto EnumValuesSizeBytes = sizeof(IDAMappingsLayouts::EnumValue) * EnumInfo->NumValues;

	if (!CanReadData(EnumValuesStart, EnumValuesSizeBytes))
		return nullptr;

	OuEnumDataEnd = EnumValuesStart + EnumValuesSizeBytes;

	return EnumInfo;
}

void IDAMappingsParser::ParseAllEnumsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::Enum&)> Callback)
{
	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return;

	IDAMappingsLayouts::OffsetType CurrentOffset = Header->EnumDataOffset;

	for (uint32_t i = 0; i < Header->NumEnums; i++)
	{
		// ParseSingleEnum updates CurrentOffset to point to the next struct
		const IDAMappingsLayouts::Enum* EnumInfo = ParseSingleEnum(CurrentOffset, CurrentOffset);

		if (!EnumInfo)
			break;

		Callback(*this, *EnumInfo);
	}
}


void IDAMappingsParser::ParseAllExecFunctionsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::ExecFunc&)> Callback)
{
	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return;

	for (uint32_t i = 0; i < Header->NumGlobalSymbols; i++)
	{
		const auto CurrentExecFuncDataOffset = Header->GlobalSymbolDataOffset + (i * sizeof(IDAMappingsLayouts::ExecFunc));
		const IDAMappingsLayouts::ExecFunc* ExecFuncInfo = GetDataAtOffset<IDAMappingsLayouts::ExecFunc>(CurrentExecFuncDataOffset);

		if (!ExecFuncInfo)
			break;

		Callback(*this, *ExecFuncInfo);
	}
}

void IDAMappingsParser::ParseAllGlobalSymbols(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::NamedVariable&)> Callback)
{
	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return;

	for (uint32_t i = 0; i < Header->NumGlobalSymbols; i++)
	{
		const auto CurrentGlobalSymbolOffset = Header->GlobalSymbolDataOffset + (i * sizeof(IDAMappingsLayouts::NamedVariable));
		const IDAMappingsLayouts::NamedVariable* GlobalSymbolInfo = GetDataAtOffset<IDAMappingsLayouts::NamedVariable>(CurrentGlobalSymbolOffset);

		if (!GlobalSymbolInfo)
			break;

		Callback(*this, *GlobalSymbolInfo);
	}
}


void IDAMappingsParser::DEBUG_DumpNamesToOutputStream(std::ostream& OutputStream) const
{
	const IDAMappingsLayouts::IDAMappingsHeader* Header = GetHeader();
	if (!Header)
		return;

	IDAMappingsLayouts::StringOffset StrOffset = 0x0;

	while ((StrOffset + sizeof(IDAMappingsLayouts::StringData::StrLenth)) < Header->StringDataSizeBytes)
	{
		const IDAMappingsLayouts::StringData* Str = GetDataAtOffset<IDAMappingsLayouts::StringData>(Header->StringDataOffset + StrOffset);
		if (!Str)
			break;

		const uint32_t LastAccessedByteOffset = StrOffset + sizeof(Str->StrLenth) + Str->StrLenth;

		if (LastAccessedByteOffset >= Header->StringDataSizeBytes || !CanReadData(StrOffset + sizeof(IDAMappingsLayouts::StringData::StrLenth), Str->StrLenth))
			break;

		OutputStream << std::format("[0x{:04X}] {}\n", Str->StrLenth, std::string_view(Str->Utf8StrData, Str->StrLenth));
	}

	OutputStream.flush();
}

