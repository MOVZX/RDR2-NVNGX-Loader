#pragma once

#include <windows.h>
#include <vector>

using std::memset, std::memcpy, std::size;

namespace hook
{
    template<typename AddressType>
    inline void nop(AddressType address, size_t length)
    {
        DWORD oldProtect;
        VirtualProtect((void*)address, length, PAGE_EXECUTE_READWRITE, &oldProtect);

        memset((void*)address, 0x90, length);

        VirtualProtect((void*)address, length, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (void*)address, length);
    }

    template<typename ValueType, typename AddressType>
    inline void put(AddressType address, ValueType value)
    {
        DWORD oldProtect;
        VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

        memcpy((void*)address, &value, sizeof(value));

        VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(value));
    }

    template<typename T, size_t Bytes, typename AddressType>
    inline void patch(AddressType address, const T(&patch)[Bytes])
    {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(address), size(patch), PAGE_EXECUTE_READWRITE, &oldProtect);

        memcpy(reinterpret_cast<void*>(address), patch, size(patch));

        VirtualProtect(reinterpret_cast<void*>(address), size(patch), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size(patch));
    }
}