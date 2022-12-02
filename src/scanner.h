#pragma once

#include <windows.h>
#include <algorithm>
#include <string_view>
#include <stdexcept>
#include <vector>

using std::wstring_view, std::string_view;

namespace scanner
{
    uintptr_t GetAddress(const wstring_view moduleName, const string_view pattern, ptrdiff_t offset = 0);
    uintptr_t GetOffsetFromInstruction(const wstring_view moduleName, const string_view pattern, ptrdiff_t offset = 0);
}