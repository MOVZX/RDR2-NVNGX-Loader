#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <memory>

using std::wstring_view;

namespace tomlConfig
{
    struct tomlSettings
    {
        // [nvngx_loader_options]
        bool Disable_NVNGX_Checks;
        bool Disable_DLSS_Sharpening_and_AutoExposure;
    };

    bool Initialize();
    bool LoadTomlFile(const wstring_view FilePath);
}

extern tomlConfig::tomlSettings Configuration;