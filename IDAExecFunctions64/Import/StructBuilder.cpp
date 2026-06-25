#include <format>
#include <string>
#include <vector>
#include <unordered_map>

#include <Import/StructBuilder.hpp>
#include <Import/TypeHelpers.hpp>

#include <Format/Parser.hpp>

uint32_t ComputeTotalSize(size_t Index, std::vector<CollectedStruct>& Structs, const std::unordered_map<std::string, size_t>& NameMap, bool bRelativeMode)
{
	if (Structs[Index].TotalSize > 0)
		return Structs[Index].TotalSize;

	const uint32_t OwnSize = static_cast<uint32_t>(Structs[Index].FileSize);

	if (Structs[Index].SuperName.empty())
	{
		Structs[Index].TotalSize = OwnSize;
		return OwnSize;
	}

	auto It = NameMap.find(Structs[Index].SuperName);
	if (It == NameMap.end())
	{
		Structs[Index].TotalSize = OwnSize;
		return OwnSize;
	}

	const uint32_t SuperTotal = ComputeTotalSize(It->second, Structs, NameMap, bRelativeMode);

	if (bRelativeMode)
		Structs[Index].TotalSize = SuperTotal + OwnSize;
	else
		Structs[Index].TotalSize = OwnSize;

	return Structs[Index].TotalSize;
}

void ForwardDeclareStruct(const CollectedStruct& CS)
{
	udt_type_data_t Fwd;
	Fwd.total_size = CS.TotalSize;
	Fwd.unpadded_size = CS.TotalSize;
	Fwd.taudt_bits |= TAUDT_CPPOBJ;

	tinfo_t Type;
	if (Type.create_udt(Fwd, BTF_STRUCT))
		Type.set_named_type(nullptr, CS.Name.c_str(), NTF_TYPE);
}

static bool BuildAndSaveStruct(udt_type_data_t& Udt, const char* Name, int NtfFlags)
{
	std::sort(Udt.begin(), Udt.end(), [](const udm_t& A, const udm_t& B) { return A.offset < B.offset; });

	tinfo_t Type;
	if (!Type.create_udt(Udt, BTF_STRUCT))
	{
		msg("[IDAMappingsImporter] create_udt failed for '%s' (%zu members, size=%u)\n", Name, Udt.size(), static_cast<unsigned>(Udt.total_size));
		return false;
	}

	tinfo_code_t Result = Type.set_named_type(nullptr, Name, NtfFlags);
	if (Result != TERR_OK)
	{
		msg("[IDAMappingsImporter] set_named_type failed for '%s': %s\n", Name, tinfo_errstr(Result));
		return false;
	}

	return true;
}

static tinfo_t ResolveMemberType(const MappingParser& Parser, const IDAMappingsLayouts::Member& Member)
{
	using namespace TypeHelpers;

	const std::string MemberType(Parser.GetNameFromOffset(Member.Type));
	const uint32_t ElementSize = static_cast<uint32_t>(Member.Size);
	const uint32_t ArrayDim = static_cast<uint32_t>(Member.ArrayDim);

	if (Member.BitFieldBitCount != 0xFF)
		return ResolveType(MemberType, ElementSize);

	if (Member.bIsPointer)
		return ResolvePointerType(MemberType, ArrayDim);

	if (ArrayDim > 1)
		return MakeArray(ResolveType(MemberType, ElementSize), ArrayDim);

	return ResolveType(MemberType, ElementSize);
}

static void AddBytePadding(udt_type_data_t& Udt, uint32 Offset, uint32 Size)
{
	using namespace TypeHelpers;

	udm_t Pad;
	Pad.name = std::format("Pad_{:X}", Offset).c_str();
	Pad.offset = static_cast<uint64>(Offset) * 8;
	Pad.type = MakeArray(MakeBasicType(BT_INT8 | BTMT_USIGNED), Size);
	Pad.size = static_cast<uint64>(Size) * 8;
	Udt.push_back(std::move(Pad));
}

static void AddBitPadding(udt_type_data_t& Udt, uint32 ByteOffset, uint8 BitIndex)
{
	udm_t Pad;
	Pad.name = std::format("BitPad_{:X}_{}", ByteOffset, BitIndex).c_str();
	Pad.offset = static_cast<uint64>(ByteOffset) * 8 + BitIndex;
	Pad.size = 1;
	Pad.type.create_bitfield(1, 1, true);
	Udt.push_back(std::move(Pad));
}

struct TempMember
{
	std::string Name;
	tinfo_t Type;
	uint32_t Offset;
	uint32_t Size;
	uint8_t BitFieldBitIndex;
};

void PopulateStruct(const MappingParser& Parser, const CollectedStruct& CS, const std::vector<CollectedStruct>& Structs, const std::unordered_map<std::string, size_t>& NameMap, bool bRelativeMode)
{
	using namespace TypeHelpers;

	const IDAMappingsLayouts::Struct& Struct = *CS.Raw;

	uint32_t SuperTotalSize = 0;
	if (!CS.SuperName.empty())
	{
		auto It = NameMap.find(CS.SuperName);
		if (It != NameMap.end())
			SuperTotalSize = Structs[It->second].TotalSize;
	}

	udt_type_data_t Udt;
	Udt.total_size = CS.TotalSize;
	Udt.unpadded_size = CS.TotalSize;
	Udt.taudt_bits |= TAUDT_CPPOBJ;

	if (CS.Alignment > 0)
		Udt.effalign = static_cast<uint32>(CS.Alignment);

	uint32_t CurrentEnd = 0;

	if (!CS.SuperName.empty() && SuperTotalSize > 0)
	{
		tinfo_t SuperType;

		if (FindType(CS.SuperName, SuperType))
		{
			udm_t Base;
			Base.offset = 0;
			Base.type = SuperType;
			Base.size = static_cast<uint64>(SuperTotalSize) * 8;
			Base.set_baseclass();
			Udt.push_back(std::move(Base));
		}

		CurrentEnd = SuperTotalSize;
	}

	std::vector<TempMember> Members;
	for (int i = 0; i < Struct.NumMembers; i++)
	{
		const IDAMappingsLayouts::Member& Member = Struct.Members[i];
		const std::string MemberName(Parser.GetNameFromOffset(Member.Name));

		if (MemberName.empty() || Parser.GetNameFromOffset(Member.Type).empty())
			continue;

		const uint32_t MemberOffset = bRelativeMode ? static_cast<uint32_t>(Member.Offset) + SuperTotalSize : static_cast<uint32_t>(Member.Offset);

		Members.push_back({
			MemberName,
			ResolveMemberType(Parser, Member),
			MemberOffset,
			static_cast<uint32>(Member.Size) * static_cast<uint32>(Member.ArrayDim),
			Member.BitFieldBitCount
		});
	}

	std::sort(Members.begin(), Members.end(), [](const TempMember& A, const TempMember& B) { return A.Offset != B.Offset ? A.Offset < B.Offset : A.BitFieldBitIndex < B.BitFieldBitIndex; });

	uint8_t NextExpectedBit = 0;
	uint32_t CurrentBitfieldByte = UINT32_MAX;

	for (const auto& Member : Members)
	{
		if (Member.Offset != CurrentBitfieldByte || Member.BitFieldBitIndex == 0xFF)
		{
			NextExpectedBit = 0;
			CurrentBitfieldByte = UINT32_MAX;
		}

		if (Member.Offset > CurrentEnd)
			AddBytePadding(Udt, CurrentEnd, Member.Offset - CurrentEnd);

		if (Member.BitFieldBitIndex != 0xFF)
		{
			CurrentBitfieldByte = Member.Offset;

			while (NextExpectedBit < Member.BitFieldBitIndex)
				AddBitPadding(Udt, Member.Offset, NextExpectedBit++);

			udm_t BitMember;
			BitMember.name = Member.Name.c_str();
			BitMember.offset = static_cast<uint64>(Member.Offset) * 8 + Member.BitFieldBitIndex;
			BitMember.size = 1;
			BitMember.type.create_bitfield(1, 1, true);
			Udt.push_back(std::move(BitMember));
			NextExpectedBit = Member.BitFieldBitIndex + 1;
		}
		else
		{
			udm_t ByteMember;
			ByteMember.name = Member.Name.c_str();
			ByteMember.offset = static_cast<uint64>(Member.Offset) * 8;
			ByteMember.type = Member.Type;
			ByteMember.size = static_cast<uint64>(Member.Size) * 8;
			Udt.push_back(std::move(ByteMember));
		}

		const uint32 MemberEnd = Member.Offset + Member.Size;
		if (MemberEnd > CurrentEnd)
			CurrentEnd = MemberEnd;
	}

	if (CurrentEnd < CS.TotalSize)
		AddBytePadding(Udt, CurrentEnd, CS.TotalSize - CurrentEnd);

	BuildAndSaveStruct(Udt, CS.Name.c_str(), NTF_TYPE | NTF_REPLACE);
}
