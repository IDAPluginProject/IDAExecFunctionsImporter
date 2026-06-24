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

inline std::map<std::string, std::map<ea_t, ExecFuncSignature>> GExecSignaturesByIdb;

inline std::map<ea_t, ExecFuncSignature>& CurrentIdbSignatures()
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
	CurrentIdbSignatures()[ThunkEA] = ParseExecSignature(Encoded);
}

inline bool ApplyExecSignature(ea_t Target, const std::string& ClassName, const ExecFuncSignature& Sig)
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

	return apply_tinfo(Target, FuncType, TINFO_DEFINITE);
}
