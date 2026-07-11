#pragma once
#define __EA64__

#include <vector>
#include <stop_token>
#include <cstdint>


#include <ida.hpp>

// Defined in main.cpp
inline bool GHasCppSDKTypes = false;

void LoadMappings(std::vector<uint8_t>&& Buffer, ea_t ImageBase, bool bImportTypes);
