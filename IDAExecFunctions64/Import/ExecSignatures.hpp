#pragma once

#include <cstdlib>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <typeinf.hpp>
#include <loader.hpp>

#include <Import/TypeHelpers.hpp>

struct ExecFuncSignature
{
	struct Param
	{
		std::string Type;
		std::string Name;
		bool        bIsPtr   = false;
		uint32      ArrayDim = 1;
	};

	std::string        ReturnType   = "void";
	bool               bReturnIsPtr = false;
	bool               bIsStatic    = false;
	std::vector<Param> Params;
};

struct RegisteredExecSignature
{
	bool              bHasCppTypeSignature = false;
	bool              bHasFallbackSignature = false;
	bool              bHasCppUnmangledName = false;
	std::string       CppTypeSignature;
	std::string       CppUnmangledName;
	ExecFuncSignature FallbackSignature;
};

inline std::map<std::string, std::map<ea_t, RegisteredExecSignature>> GExecSignaturesByIdb;

inline std::map<ea_t, RegisteredExecSignature>& CurrentIdbSignatures()
{
	const char* IdbPath = get_path(PATH_TYPE_IDB);
	return GExecSignaturesByIdb[IdbPath ? IdbPath : ""];
}

namespace ExecSignatureDetail
{
	inline std::vector<std::string> Split(std::string_view Text, char Delimiter)
	{
		std::vector<std::string> Parts;
		size_t Start = 0;

		while (true)
		{
			const size_t End = Text.find(Delimiter, Start);
			Parts.emplace_back(Text.substr(Start, End - Start));

			if (End == std::string_view::npos)
				break;

			Start = End + 1;
		}

		return Parts;
	}
}

inline ExecFuncSignature ParseExecSignature(std::string_view Encoded)
{
	ExecFuncSignature Sig;

	const std::vector<std::string> Blocks = ExecSignatureDetail::Split(Encoded, '\x1e');
	if (Blocks.empty())
		return Sig;

	// Block 0 is the return value: "Type\x1fIsPtr\x1fIsStatic"
	const std::vector<std::string> ReturnFields = ExecSignatureDetail::Split(Blocks[0], '\x1f');

	if (!ReturnFields.empty() && !ReturnFields[0].empty())
		Sig.ReturnType = ReturnFields[0];
	if (ReturnFields.size() > 1)
		Sig.bReturnIsPtr = (ReturnFields[1] == "1");
	if (ReturnFields.size() > 2)
		Sig.bIsStatic = (ReturnFields[2] == "1");

	// Blocks 1.. are params: "Type\x1fName\x1fIsPtr\x1fArrayDim"
	for (size_t i = 1; i < Blocks.size(); i++)
	{
		const std::vector<std::string> Fields = ExecSignatureDetail::Split(Blocks[i], '\x1f');
		if (Fields.size() < 4)
			continue;

		ExecFuncSignature::Param P;
		P.Type   = Fields[0];
		P.Name   = Fields[1];
		P.bIsPtr = (Fields[2] == "1");

		const int Dim = std::atoi(Fields[3].c_str());
		P.ArrayDim = static_cast<uint32>(Dim > 0 ? Dim : 1);

		Sig.Params.push_back(std::move(P));
	}

	return Sig;
}

inline void RegisterExecSignature(ea_t ThunkEA, std::string_view Encoded)
{
	RegisteredExecSignature& Signature = CurrentIdbSignatures()[ThunkEA];
	Signature.FallbackSignature = ParseExecSignature(Encoded);
	Signature.bHasFallbackSignature = true;
}

inline void RegisterExecCppTypeSignature(
	ea_t ThunkEA,
	std::string_view CppTypeSignature,
	std::string_view UnmangledName = {})
{
	RegisteredExecSignature& Signature = CurrentIdbSignatures()[ThunkEA];
	Signature.CppTypeSignature = CppTypeSignature;
	Signature.bHasCppTypeSignature = true;
	Signature.CppUnmangledName = UnmangledName;
	Signature.bHasCppUnmangledName = !UnmangledName.empty();
}

inline bool MakeExecSignatureType(tinfo_t* OutType, const std::string& ClassName, const ExecFuncSignature& Sig)
{
	using namespace TypeHelpers;

	func_type_data_t FuncData;
	FuncData.set_cc(CM_CC_FASTCALL);

	if (Sig.bReturnIsPtr)
		FuncData.rettype = ResolvePointerType(Sig.ReturnType, 1);
	else if (Sig.ReturnType == "void")
		FuncData.rettype = MakeBasicType(BT_VOID);
	else
		FuncData.rettype = ResolveType(Sig.ReturnType, 0);

	if (!Sig.bIsStatic && !ClassName.empty())
	{
		funcarg_t ThisArg;
		ThisArg.type = ResolvePointerType(ClassName, 1);
		ThisArg.name = "this";
		FuncData.push_back(ThisArg);
	}

	for (const ExecFuncSignature::Param& P : Sig.Params)
	{
		funcarg_t Arg;
		Arg.type = P.bIsPtr ? ResolvePointerType(P.Type, P.ArrayDim) : ResolveType(P.Type, P.ArrayDim);
		Arg.name = P.Name.c_str();
		FuncData.push_back(Arg);
	}

	tinfo_t FuncType;
	if (!FuncType.create_func(FuncData))
		return false;

	*OutType = FuncType;
	return true;
}

inline bool ApplyExecSignature(ea_t Target, const std::string& ClassName, const ExecFuncSignature& Sig)
{
	tinfo_t FuncType;
	if (!MakeExecSignatureType(&FuncType, ClassName, Sig))
		return false;

	return apply_tinfo(Target, FuncType, TINFO_DEFINITE);
}

inline bool MakeCppTypeSignature(tinfo_t* OutType, const std::string& Signature)
{
	tinfo_t FuncType;
	qstring OutName;
	if (!parse_decl(&FuncType, &OutName, get_idati(), Signature.c_str(), PT_SIL | PT_VAR | PT_HIGH | PT_NDC | PT_RELAXED | PT_SEMICOLON))
		return false;

	*OutType = FuncType;
	return true;
}

inline bool ApplyCppTypeSignature(ea_t Target, const std::string& Signature)
{
	tinfo_t FuncType;
	if (!MakeCppTypeSignature(&FuncType, Signature))
		return false;

	return apply_tinfo(Target, FuncType, TINFO_DEFINITE);
}

inline bool MakeRegisteredExecSignatureType(tinfo_t* OutType, const std::string& ClassName, const RegisteredExecSignature& Signature, bool bHasCppSDKTypes)
{
	if (bHasCppSDKTypes && Signature.bHasCppTypeSignature)
		return MakeCppTypeSignature(OutType, Signature.CppTypeSignature);

	if (Signature.bHasFallbackSignature)
		return MakeExecSignatureType(OutType, ClassName, Signature.FallbackSignature);

	return false;
}

inline bool IsRegisteredExecCppSignatureSelected(const RegisteredExecSignature& Signature, bool bHasCppSDKTypes)
{
	return bHasCppSDKTypes && Signature.bHasCppTypeSignature;
}

inline std::string DescribeExecSignatureParam(const ExecFuncSignature::Param& Param)
{
	std::string Text = Param.Type;
	if (Param.bIsPtr)
		Text += "*";
	if (Param.ArrayDim > 1)
		Text += "[" + std::to_string(Param.ArrayDim) + "]";
	if (!Param.Name.empty())
		Text += " " + Param.Name;
	return Text;
}

inline std::string DescribeFallbackExecSignature(const std::string& ClassName, const ExecFuncSignature& Signature)
{
	std::string Text = Signature.ReturnType;
	if (Signature.bReturnIsPtr)
		Text += "*";
	Text += " __fastcall(";

	bool bHasParam = false;
	if (!Signature.bIsStatic && !ClassName.empty())
	{
		Text += ClassName + "* this";
		bHasParam = true;
	}

	for (const ExecFuncSignature::Param& Param : Signature.Params)
	{
		if (bHasParam)
			Text += ", ";
		Text += DescribeExecSignatureParam(Param);
		bHasParam = true;
	}

	Text += ")";
	return Text;
}

inline std::string DescribeRegisteredExecSignature(const std::string& ClassName, const RegisteredExecSignature& Signature, bool bHasCppSDKTypes)
{
	if (IsRegisteredExecCppSignatureSelected(Signature, bHasCppSDKTypes))
		return Signature.CppTypeSignature;

	if (Signature.bHasFallbackSignature)
		return DescribeFallbackExecSignature(ClassName, Signature.FallbackSignature);

	return std::string();
}

inline const std::string* GetRegisteredExecCppUnmangledName(const RegisteredExecSignature& Signature, bool bHasCppSDKTypes)
{
	return (bHasCppSDKTypes && Signature.bHasCppTypeSignature && Signature.bHasCppUnmangledName)
		? &Signature.CppUnmangledName
		: nullptr;
}

inline bool ApplyRegisteredExecSignature(ea_t Target, const std::string& ClassName, const RegisteredExecSignature& Signature, bool bHasCppSDKTypes)
{
	tinfo_t FuncType;
	if (!MakeRegisteredExecSignatureType(&FuncType, ClassName, Signature, bHasCppSDKTypes))
		return false;

	return apply_tinfo(Target, FuncType, TINFO_DEFINITE);
}
