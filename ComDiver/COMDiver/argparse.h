#pragma once
#include <algorithm>
#include <string>

bool cmdOptionExists(wchar_t** begin, wchar_t** end, const std::wstring& option);
wchar_t* getCmdOption(wchar_t** begin, wchar_t** end, const std::wstring& option);