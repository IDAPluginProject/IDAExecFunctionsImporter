#pragma once
#define __EA64__

#include "IDAMappingLayout.hpp"

#include <vector>
#include <string>
#include <iosfwd>
#include <cstddef>

class MappingParser
{
private:
	std::vector<uint8_t> Buffer;

	const IDAMappingsLayouts::IDAMappingsHeader* GetHeader() const
	{
		// Validate only the v1 header fields here; the appended v2 field (ExecFuncSignatureDataOffset) is read separately under a version guard
		if (!CanReadData(0x0, offsetof(IDAMappingsLayouts::IDAMappingsHeader, ExecFuncSignatureDataOffset)))
			return nullptr;

		return reinterpret_cast<const IDAMappingsLayouts::IDAMappingsHeader*>(Buffer.data());
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
	
	const IDAMappingsLayouts::Struct* ParseSingleStruct(IDAMappingsLayouts::OffsetType CurrentStructStart, IDAMappingsLayouts::OffsetType& OutStructDataEnd);
	const IDAMappingsLayouts::Enum* ParseSingleEnum(IDAMappingsLayouts::OffsetType CurrentEnumStart, IDAMappingsLayouts::OffsetType& OutEnumDataEnd);

public:
	explicit MappingParser(std::vector<uint8_t> InBuffer) : Buffer(std::move(InBuffer)) {}

	bool IsValidHeader() const;

	std::string_view GetNameFromOffset(IDAMappingsLayouts::StringOffset NameOffset) const;

	std::vector<const IDAMappingsLayouts::Struct*> GetAllStructs();
	std::vector<const IDAMappingsLayouts::Enum*> GetAllEnums();
	std::vector<const IDAMappingsLayouts::ExecFunc*> GetAllExecFunctions();
	std::vector<const IDAMappingsLayouts::NamedVariable*> GetAllGlobalSymbols();
	IDAMappingsLayouts::StringOffset GetExecFuncSignatureOffset(uint32_t Index) const;
};
