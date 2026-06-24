#pragma once
#define __EA64__

#include "Format.hpp"

#include <vector>
#include <string>
#include <iosfwd>
#include <cstddef>

class MappingParser
{
private:
	std::vector<uint8_t> Buffer;

	const MappingLayouts::IDAMappingsHeader* GetHeader() const
	{
		// Validate only the v1 header fields here; the appended v2 field (ExecFuncSignatureDataOffset) is read separately under a version guard
		if (!CanReadData(0x0, offsetof(MappingLayouts::IDAMappingsHeader, ExecFuncSignatureDataOffset)))
			return nullptr;

		return reinterpret_cast<const MappingLayouts::IDAMappingsHeader*>(Buffer.data());
	}

	bool CanReadData(size_t Offset, size_t Size) const
	{
		return Offset <= Buffer.size() && Size <= (Buffer.size() - Offset);
	}

	template<typename T>
	const T* GetDataAtOffset(size_t AbsoluteOffset) const
	{
		if (CanReadData(AbsoluteOffset, sizeof(T)))
			return reinterpret_cast<const T*>(Buffer.data() + AbsoluteOffset);

		return nullptr;
	}
	
	const MappingLayouts::Struct* ParseSingleStruct(MappingLayouts::OffsetType CurrentStructStart, MappingLayouts::OffsetType& OutStructDataEnd);
	const MappingLayouts::Enum* ParseSingleEnum(MappingLayouts::OffsetType CurrentEnumStart, MappingLayouts::OffsetType& OutEnumDataEnd);

public:
	explicit MappingParser(std::vector<uint8_t> InBuffer) : Buffer(std::move(InBuffer)) {}

	bool IsValidHeader() const;

	std::string_view GetNameFromOffset(MappingLayouts::StringOffset NameOffset) const;

	std::vector<const MappingLayouts::Struct*> GetAllStructs();
	std::vector<const MappingLayouts::Enum*> GetAllEnums();
	std::vector<const MappingLayouts::ExecFunc*> GetAllExecFunctions();
	std::vector<const MappingLayouts::NamedVariable*> GetAllGlobalSymbols();
	MappingLayouts::StringOffset GetExecFuncSignatureOffset(uint32_t Index) const;
};
