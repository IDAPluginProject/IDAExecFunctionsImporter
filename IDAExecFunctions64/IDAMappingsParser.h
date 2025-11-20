#pragma once

#include "IDAMappingStructs.h"

#include <vector>
#include <string>
#include <functional>

#include "ida_file.h"

class IDAMappingsParser
{
private:
	std::vector<uint8_t> Buffer;

public:
	IDAMappingsParser(ida_file& File)
		: Buffer(File.read_into_buffer())
	{
	}

private:
	inline const IDAMappingsLayouts::IDAMappingsHeader* GetHeader() const
	{
		return GetDataAtOffset<IDAMappingsLayouts::IDAMappingsHeader>(0x0);
	}

	inline bool CanReadData(const uint32_t Offset, const uint32_t Size) const
	{
		return Buffer.size() >= (static_cast<size_t>(Offset) + Size);
	}

	template<typename T>
	inline const T* GetDataAtOffset(const uint32_t AbsoluteOffset) const
	{
		if (CanReadData(AbsoluteOffset, sizeof(T)))
			return reinterpret_cast<const T*>(Buffer.data());

		return nullptr;
	}

private:
	const IDAMappingsLayouts::Struct* ParseSingleStruct(const IDAMappingsLayouts::OffsetType CurrentStructStart, IDAMappingsLayouts::OffsetType& OutStructDataEnd);
	const IDAMappingsLayouts::Enum* ParseSingleEnum(const IDAMappingsLayouts::OffsetType CurrentEnumStart, IDAMappingsLayouts::OffsetType& OuEnumDataEnd);

public:
	std::string_view GetNameFromOffset(const IDAMappingsLayouts::StringOffset NameOffset) const;

	void ParseAllStructsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::Struct&)> Callback);
	void ParseAllEnumsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::Enum&)> Callback);
	void ParseAllExecFunctionsWithCallback(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::ExecFunc&)> Callback);
	void ParseAllGlobalSymbols(std::function<void(const IDAMappingsParser&, const IDAMappingsLayouts::NamedVariable&)> Callback);

public:
	void DEBUG_DumpNamesToOutputStream(std::ostream& OutputStream) const;
};

