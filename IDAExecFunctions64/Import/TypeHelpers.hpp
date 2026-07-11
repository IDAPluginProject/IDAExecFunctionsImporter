#pragma once

#include <typeinf.hpp>
#include <string>
#include <string_view>

namespace TypeHelpers
{
	inline tinfo_t MakeBasicType(type_t DeclType)
	{
		tinfo_t Type;
		Type.create_simple_type(DeclType);
		return Type;
	}

	inline tinfo_t MakePtrTo(const tinfo_t& Pointee)
	{
		tinfo_t Type;
		Type.create_ptr(Pointee);
		return Type;
	}

	inline tinfo_t MakeArray(const tinfo_t& Element, uint32 Count)
	{
		tinfo_t Type;
		Type.create_array(Element, Count);
		return Type;
	}

	inline bool LookupType(const char* Name, tinfo_t& OutType)
	{
		return OutType.get_named_type(nullptr, Name, BTF_TYPEDEF, true, true);
	}

	inline bool FindType(const std::string& Name, tinfo_t& OutType)
	{
		if (LookupType(Name.c_str(), OutType))
			return true;

		return LookupType(("struct " + Name).c_str(), OutType);
	}

	inline tinfo_t ResolveBasicType(std::string_view TypeName)
	{
		if (TypeName == "unsigned __int8")	return MakeBasicType(BT_INT8 | BTMT_USIGNED);
		if (TypeName == "__int8")			return MakeBasicType(BT_INT8 | BTMT_SIGNED);
		if (TypeName == "unsigned __int16") return MakeBasicType(BT_INT16 | BTMT_USIGNED);
		if (TypeName == "__int16")			return MakeBasicType(BT_INT16 | BTMT_SIGNED);
		if (TypeName == "int")				return MakeBasicType(BT_INT32 | BTMT_SIGNED);
		if (TypeName == "unsigned int")		return MakeBasicType(BT_INT32 | BTMT_USIGNED);
		if (TypeName == "__int64")			return MakeBasicType(BT_INT64 | BTMT_SIGNED);
		if (TypeName == "unsigned __int64") return MakeBasicType(BT_INT64 | BTMT_USIGNED);
		if (TypeName == "float")			return MakeBasicType(BT_FLOAT | BTMT_FLOAT);
		if (TypeName == "double")			return MakeBasicType(BT_FLOAT | BTMT_DOUBLE);
		if (TypeName == "bool")				return MakeBasicType(BT_INT8 | BTMT_USIGNED);
		if (TypeName == "char")				return MakeBasicType(BT_INT8 | BTMT_CHAR);
		if (TypeName == "wchar_t")			return MakeBasicType(BT_INT16 | BTMT_USIGNED);

		return tinfo_t();
	}

	inline tinfo_t ResolveType(std::string_view TypeName, uint32 FallbackSize)
	{
		tinfo_t Basic = ResolveBasicType(TypeName);
		if (Basic.present())
			return Basic;

		tinfo_t Resolved;
		if (LookupType(std::string(TypeName).c_str(), Resolved))
			return Resolved;

		if (TypeName.substr(0, 7) == "struct ")
		{
			if (LookupType(std::string(TypeName.substr(7)).c_str(), Resolved))
				return Resolved;
		}

		if (FallbackSize > 0)
			return MakeArray(MakeBasicType(BT_INT8 | BTMT_USIGNED), FallbackSize);

		return MakeBasicType(BT_INT8 | BTMT_USIGNED);
	}

	inline tinfo_t ResolvePointerType(std::string_view TypeName, uint32 ArrayDim)
	{
		std::string_view Pointee = TypeName;
		if (Pointee.substr(0, 7) == "struct ")
			Pointee = Pointee.substr(7);

		int ExtraLevels = 0;
		while (!Pointee.empty() && Pointee.back() == '*')
		{
			Pointee.remove_suffix(1);
			ExtraLevels++;
		}

		tinfo_t Base;
		if (Pointee == "void")
		{
			Base = MakeBasicType(BT_VOID);
		}
		else
		{
			if (!LookupType(std::string(Pointee).c_str(), Base))
			{
				if (!LookupType(("struct " + std::string(Pointee)).c_str(), Base))
					Base = MakeBasicType(BT_VOID);
			}
		}

		for (int i = 0; i < ExtraLevels; i++)
			Base = MakePtrTo(Base);

		tinfo_t Ptr = MakePtrTo(Base);

		if (ArrayDim > 1)
			return MakeArray(Ptr, ArrayDim);

		return Ptr;
	}
}
