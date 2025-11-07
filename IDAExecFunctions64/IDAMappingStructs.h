#pragma once
#include <cstdint>

using StringOffset = uint32_t;
using OffsetType = uint32_t;
using InternalOffset = uint32_t;

struct Member
{
	StringOffset Type;
	StringOffset Name;

	int32_t Offset;
	int32_t Size;
	int32_t ArrayDim;
	bool bIsPointer;
	uint8_t BitFieldBitCount; // 0xFF by default if this isn't a bitfield
};

struct Struct
{
	StringOffset Name;
	StringOffset SuperName;

	int32_t Size;
	int32_t Alignment;

	int32_t NumMembers;
	Member Members[1];
};

struct EnumValue
{
	StringOffset Name;
	int64_t Value;
};

struct Enum
{
	StringOffset Name;

	int32_t NumValues;
	EnumValue Values[1];
};

struct ExecFunc
{
	StringOffset MangledName;
	OffsetType OffsetRelativeToImagebase;
};

// VTables, GWorld, GNames, etc.
struct NamedVariable
{
	OffsetType VariableOffset;

	StringOffset Type;
	StringOffset Name;
};

struct StringData
{
	uint16_t StrLenth;
	const char Utf8StrData[1];
};

struct IDAMappingsHeader
{
	uint32_t StringDataSizeBytes;
	InternalOffset StringDataOffset;

	uint32_t NumEnums;
	InternalOffset EnumDataOffset;

	uint32_t NumStructs;
	InternalOffset StructDataOffset;

	uint32_t NumGlobalSymbols;
	InternalOffset GlobalSymbolDataOffset;

	uint32_t NumExecFunctions;
	InternalOffset ExecFunctionDataOffset;
};

// This struct is just an example of the later layout of data, don't use this
struct FileData
{
	IDAMappingsHeader Header;

	uint8_t Strings[1];
	Enum Enums[1];
	Struct Structs[1];
	NamedVariable GlobalSymbols[1];
	ExecFunc ExecFunctions[1];
};

