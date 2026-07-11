#pragma once

#define __EA64__

/*
 * Note: The content of both StaticClassNamer.hpp and StaticClassNamer.cpp is AI generated
 */

/* Applies name and type to USomeClass::StaticClass() functions. */
bool NameAllStaticClassFunctions();

/* Forward-declared so the prefix-cache builder can take a parser by reference. */
class MappingParser;

/* Fills the StaticClass prefix cache from the .idmap struct table (raw name -> C++ prefix). */
void BuildStaticClassPrefixCache(MappingParser& Parser);

/* Empties the prefix cache; call once at the start of each import run. */
void ClearStaticClassPrefixCache();
