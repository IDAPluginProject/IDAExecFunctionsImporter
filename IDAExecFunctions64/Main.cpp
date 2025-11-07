#include <Windows.h>

// Makes ea_t an uint64 for high base address images
#define __EA64__
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>

#include <typeinf.hpp>
#include <nalt.hpp>

#include "ida_file.h"
#include "ida_string.h"


using StructType = tinfo_t;
using StructMemberType = udm_t;
using IDAType = tinfo_t;


inline StructMemberType CreateMemberVarible(const std::string_view Name, const std::string_view TypeName, uint32_t Offset, uint32_t Size, const bool bIsPointer = false, const uint32_t ArrayDimension = 1, const uint8_t BitFieldBitIndex = 0xFF, const uint8_t BitCount = 1)
{
	if (Name.empty() || TypeName.empty())
	{
		warning("Attempted to create member with empty 'Name' or 'TypeName'\n");
		return StructMemberType{};
	}

	if (ArrayDimension > 1 && BitFieldBitIndex != 0xFF)
	{
		warning("Attempted to create member with 'ArrayDimension > 1' && 'BitFieldBitIndex != 0xFF'. Invalid combination. TypeName (%s), Name (%s)\n", TypeName.data(), Name.data());
		return StructMemberType{};
	}

	if (bIsPointer && BitFieldBitIndex != 0xFF)
	{
		warning("Attempted to create member with 'bIsPointer == true' && 'BitFieldBitIndex != 0xFF'. Invalid combination. TypeName (%s), Name (%s)\n", TypeName.data(), Name.data());
		return StructMemberType{};
	}

	StructMemberType Member;
	Member.name = Name.data();
	Member.offset = Offset;
	Member.size = Size;

	if (bIsPointer)
	{
		IDAType PtrType;
		PtrType.create_ptr(IDAType(TypeName.data()));

		if (ArrayDimension > 1)
		{
			Member.type.create_array(std::move(PtrType), ArrayDimension);
		}
		else
		{
			Member.type = std::move(PtrType);
		}
	}
	else
	{
		if (ArrayDimension > 1)
		{
			Member.type.create_array(IDAType(TypeName.data()), ArrayDimension);
		}
		else if (BitFieldBitIndex != 0xFF)
		{
			//const auto ByteIndex = BitFieldBitIndex >> 3;
			//const auto BitIndex = BitFieldBitIndex & 0b111;
			const auto ByteCount = (BitCount >> 3) + (BitCount % 0x8 != 0); // Add 1 to the byte count if there are left over bits

			Member.type.create_bitfield(ByteCount, BitCount, true);
		}
		else
		{
			Member.type = IDAType(TypeName.data());
		}
	}

	return Member;
}

StructType CreateStruct()
{
	return StructType();
}

bool create_class_type()
{
	til_t* til = get_idati();

	// Create a UDT (User Defined Type) - class/struct
	udt_type_data_t udt;
	udt.taudt_bits = TAUDT_CPPOBJ;  // C++ class

	// Add members
	udm_t m;

	// Member 1: int field1
	//m.name = "field1";
	//m.type = tinfo_t("int32_t");
	//m.offset = 0;
	//m.size = 4;
	//udt.push_back(m);
	udt.push_back(CreateMemberVarible("Field1", "int32_t", 0x0, sizeof(int32_t)));

	// Member 2: void *field2
	//m.name = "field2";
	//tinfo_t ptr_type;
	////ptr_type.create_ptr(tinfo_t(BTF_VOID));
	//ptr_type.create_ptr(tinfo_t("struct FVector"));
	//m.type = ptr_type;
	//m.offset = 4;
	//m.size = sizeof(void*);
	//udt.push_back(m);
	udt.push_back(CreateMemberVarible("Field2", "struct FVector", 0x8, sizeof(void*), true));

	// Member 3: char field3[64]
	//m.name = "field3";
	//tinfo_t arr_type;
	//arr_type.create_array(tinfo_t(BTF_CHAR), 64);
	//m.type = arr_type;
	//m.offset = 4 + sizeof(void*);
	//m.size = 64;
	//udt.push_back(m);
	udt.push_back(CreateMemberVarible("Pad", "uint8_t", 0x10, sizeof(char) * 64, false, 64));
	
	udt.push_back(CreateMemberVarible("bBitField3", "uint8_t", 0x50, sizeof(char), false, 1, 0));
	udt.push_back(CreateMemberVarible("bBitField4", "uint8_t", 0x50, sizeof(char), false, 1, 1));
	udt.push_back(CreateMemberVarible("bBitField5", "uint8_t", 0x50, sizeof(char), false, 1, 3));
	//udt.push_back(CreateMemberVarible("bBitField5", "uint8_t", 0x50, sizeof(char), false, 1, 9));

	// Create tinfo from UDT
	tinfo_t tif;
	tif.create_udt(udt, BTF_STRUCT);

	// Add to local types
	if (tif.set_named_type(til, "MyClass"))
	{
		msg("Class created successfully\n");
		return true;
	}

	return false;
}

bool create_class_with_methods()
{
	til_t* til = get_idati();

	// Create a UDT (User Defined Type)
	udt_type_data_t udt;
	udt.taudt_bits = TAUDT_CPPOBJ;  // C++ class

	udm_t m;

	// Add data members first
	m.name = "field1";
	m.type = tinfo_t(BTF_INT32);
	m.offset = 0;
	m.size = 4;
	udt.push_back(m);

	// Add a regular member function
	// Create function type: int method1(int param)
	func_type_data_t ftd;
	ftd.rettype = tinfo_t(BTF_INT32);

	funcarg_t arg;
	arg.type = tinfo_t(BTF_INT32);
	arg.name = "param";
	ftd.push_back(arg);

	tinfo_t func_type;
	func_type.create_func(ftd);
	//func_type.set_cc(CM_CC_THISCALL);  // Set calling convention separately

	m.name = "method1";
	m.type = func_type;
	m.offset = BADADDR;  // Functions don't have offsets like data members
	m.size = 0;
	m.effalign = 0;
	udt.push_back(m);

	// Add a virtual function
	// Create function type: virtual void method2()
	func_type_data_t ftd_virtual;
	ftd_virtual.rettype = tinfo_t(BTF_VOID);

	tinfo_t vfunc_type;
	vfunc_type.create_func(ftd_virtual);
	//vfunc_type.set_cc(CM_CC_THISCALL);

	m.name = "method2";
	m.type = vfunc_type;
	m.offset = BADADDR;
	m.size = 0;
	m.effalign = 0;
	// Mark as virtual - check udm_t flags in typeinf.hpp for exact flag names
	// In IDA 9.x, virtual methods may be handled differently
	udt.push_back(m);

	// Create tinfo from UDT
	tinfo_t tif;
	tif.create_udt(udt, BTF_STRUCT);

	// Add to local types
	if (tif.set_named_type(til, "MyClass2"))
	{
		msg("Class with methods created successfully\n");
		return true;
	}
	return false;
}


class plugin_ctx_t : public plugmod_t
{
public:
	// Constructor
	plugin_ctx_t()
	{
		msg("IDAExecFunctions64: Plugin loaded.\n");
	}

	// Destructor
	virtual ~plugin_ctx_t()
	{
		// msg("IDAExecFunctions64: Destructor called.\n");
	}
	virtual bool idaapi run(size_t) override
	{
		ida_string result = ask_file(false, "*.idmap", "Load the file, or %s", "die!");
		
		ida_file selected_file(result, ida_file::open_mode::binary_read_only);

		auto image_base = get_imagebase();
		msg("IDAExecFunctions64: Image base is 0x%llX\n", image_base);

		msg("IDAExecFunctions64: Applying names...\n");
		if (selected_file.is_open())
		{
			while (selected_file.can_read_more())
			{
				uint32 offset = selected_file.read<uint32>();
				uint16 name_len = selected_file.read<uint16>();

				ida_string name_string = selected_file.read_string(name_len);

				set_name(image_base + offset, name_string.c_str());

				//msg("offset: 0x%X\n", offset);
				//msg("name_len: 0x%X\n", name_len);
				//msg("name_string: %s\n", name_string.c_str());
			}
		}

		create_class_type();

		msg("IDAExecFunctions64: Done.\n");

		return true;
	}
};


//--------------------------------------------------------------------------
static plugmod_t* idaapi init(void)
{
	return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "IDAExecFunctionsImporter", // the preferred short name of the plugin
  "Ctrl-Alt-D",         // the preferred hotkey to run the plugin
};
