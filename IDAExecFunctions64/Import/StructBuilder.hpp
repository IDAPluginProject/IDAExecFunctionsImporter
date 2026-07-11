#pragma once
#define __EA64__

#include <format>
#include <stop_token>
#include <string>
#include <vector>
#include <unordered_map>

#include <ida.hpp>
#include <typeinf.hpp>

#include <Format/IDAMappingLayout.hpp>

class MappingParser;

struct CollectedStruct
{
	std::string Name;
	std::string SuperName;
	int32_t FileSize;
	int32_t Alignment;
	const IDAMappingsLayouts::Struct* Raw;
	uint32_t TotalSize;
};

uint32_t ComputeTotalSize(size_t Index, std::vector<CollectedStruct>& Structs, const std::unordered_map<std::string, size_t>& NameMap, bool bRelativeMode);

void ForwardDeclareStruct(const CollectedStruct& CS);
void PopulateStruct(const MappingParser& Parser, const CollectedStruct& CS, const std::vector<CollectedStruct>& Structs, const std::unordered_map<std::string, size_t>& NameMap, bool bRelativeMode);
