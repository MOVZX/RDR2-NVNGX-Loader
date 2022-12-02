#include "hooking.h"
#include "scanner.h"
#include "toml++.h"

using tomlConfig::Initialize;
using hook::nop, hook::put, hook::patch;
using scanner::GetAddress, scanner::GetOffsetFromInstruction;

void init()
{
    Initialize();

    if (Configuration.Disable_NVNGX_Checks)
    {
        // GPU check
        nop((GetAddress(L"RDR2.exe", "E8 ? ? ? ? 4C 8B CB 48 8D 54 24 60", -0xD)), 6);

        // Signature check
        put<uint8_t>(GetAddress(L"RDR2.exe", "80 3D ? ? ? ? ? 75 ? 41 8B CF", 6), 0x01);
    }

    if (Configuration.Disable_DLSS_Sharpening_and_AutoExposure)
    {
        /*
        * Gets addresss of the function we are patching form the calls the offset is function + 0xA9
        * We cant search originial bytes because of 3 matches 1st match is crashlog related shit
        * Originial bytes 44 8B 43 14 48 8D 15 ? ? ? ?
        * mov r8d, dword ptr ds:[rbx+0x14] 
        * lea rdx, DLSS.Feature.Create.Flags
        */

        // Vulkan
        auto loc = GetOffsetFromInstruction(L"RDR2.exe", "E8 ? ? ? ? EB ? E8 ? ? ? ? 48 ? C8 48 89", 1);

        // DirectX 12
        auto addr = GetOffsetFromInstruction(L"RDR2.exe", "8B D7 E8 ? ? ? ? 44 ? D8", 3);

        /*
        * Patched bytes: 41 B0 4B 90 48 8D 15 ? ? ? ?
        * mov r8b, 0x4B
        * nop
        * lea rdx, DLSS.Feature.Create.Flags
        */

        if (loc == NULL && addr == NULL)
            return;

        constexpr const uint8_t patchBytes[] { 0x41, 0xB0, 0x4B, 0x90, 0x48, 0x8D, 0x15 };

        patch((loc + 0xA9), patchBytes);
        patch((addr + 0xA9), patchBytes);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        init();
    }

    return TRUE;
}