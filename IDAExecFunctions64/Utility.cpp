#include "Utility.hpp"

#include <Windows.h>

#include <ida.hpp>
#include <segment.hpp>
#include <bytes.hpp>


std::string WStrToStr(const std::wstring& WStr)
{
	if (WStr.empty())
		return std::string();

	const auto SizeNeeded = WideCharToMultiByte(CP_UTF8, 0, WStr.c_str(), static_cast<int>(WStr.size()), NULL, 0, NULL, NULL);

	std::string Str(SizeNeeded, 0);
	WideCharToMultiByte(CP_UTF8, 0, WStr.c_str(), static_cast<int>(WStr.size()), Str.data(), SizeNeeded, NULL, NULL);

	return Str;
}


std::vector<ea_t> FindWideStringLiteralsByContent(const char* Str)
{
	std::vector<ea_t> Ret;

	if (!Str || Str[0] == '\0')
		return Ret;

	auto AddUniqueAddress = [&Ret](const ea_t Address)
	{
		if (Address != BADADDR && std::find(Ret.begin(), Ret.end(), Address) == Ret.end())
			Ret.push_back(Address);
	};

	std::vector<uchar> Pattern;
	for (const char* Ch = Str; *Ch; ++Ch)
	{
		Pattern.push_back(static_cast<uchar>(*Ch));
		Pattern.push_back(0);
	}
	Pattern.push_back(0);
	Pattern.push_back(0);

	for (int SegIdx = 0; SegIdx < get_segm_qty(); ++SegIdx)
	{
		segment_t* Seg = getnseg(SegIdx);
		if (!Seg || !(Seg->perm & SEGPERM_READ) || (Seg->perm & SEGPERM_EXEC))
			continue;

		ea_t SearchStart = Seg->start_ea;
		while (SearchStart < Seg->end_ea)
		{
			const ea_t Found = bin_search(
				SearchStart,
				Seg->end_ea,
				Pattern.data(),
				nullptr,
				Pattern.size(),
				BIN_SEARCH_FORWARD
			);

			if (Found == BADADDR)
				break;

			AddUniqueAddress(Found);
			SearchStart = Found + 1;
		}
	}

	return Ret;
}

bool IsValidCodePointer(ea_t Address)
{
	segment_t* Seg = getseg(Address);
	if (!Seg)
		return false;

	return Seg->type == SEG_CODE;
}
