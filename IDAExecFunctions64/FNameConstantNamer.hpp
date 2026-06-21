#pragma once

#define __EA64__

/*
 * Note: The content of both FNameConstantNamer.hpp and FNameConstantNamer.cpp is AI generated
 */

/*
 * Applies names to FName::FName(&NAME_ThisFName, L"ThisFName")
 *								  ^^^^^^^^^^^^^^
*/
bool NameAllFNameConstructorGlobals(bool AllowCursorFallback = false);