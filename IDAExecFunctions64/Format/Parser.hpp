#pragma once
#define __EA64__

#include "Format.hpp"

#include <vector>
#include <string>
#include <iosfwd>

class MappingParser
{
private:
	std::vector<uint8_t> Buffer;

	const MappingLayouts::IDAMappingsHeader* GetHeader() const
	{
		return GetDataAtOffset<MappingLayouts::IDAMappingsHeader>(0x0);
	}

	bool CanReadData(size_t Offset, size_t Size) const
	{
		return Buffer.size() >= (Offset + Size);
	}

	template<typename T>
	const T* GetDataAtOffset(uint32_t AbsoluteOffset) const
	{
		if (CanReadData(AbsoluteOffset, sizeof(T)))
			return reinterpret_cast<const T*>(Buffer.data() + AbsoluteOffset);

		return nullptr;
	}
	
	const MappingLayouts::Struct* ParseSingleStruct(MappingLayouts::OffsetType CurrentStructStart, MappingLayouts::OffsetType& OutStructDataEnd);
	const MappingLayouts::Enum* ParseSingleEnum(MappingLayouts::OffsetType CurrentEnumStart, MappingLayouts::OffsetType& OutEnumDataEnd);

public:
	explicit MappingParser(std::vector<uint8_t> InBuffer) : Buffer(std::move(InBuffer)) {}

	std::string_view GetNameFromOffset(MappingLayouts::StringOffset NameOffset) const;

	std::vector<const MappingLayouts::Struct*> GetAllStructs();
	std::vector<const MappingLayouts::Enum*> GetAllEnums();
	std::vector<const MappingLayouts::ExecFunc*> GetAllExecFunctions();
	std::vector<const MappingLayouts::NamedVariable*> GetAllGlobalSymbols();
};
