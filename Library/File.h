#pragma once

#include <vector>
#include <filesystem>

class File
{
    std::vector<std::byte> binaryData;

public:
    explicit File(const std::filesystem::path& filepath);

    constexpr auto& read()
    {
        return binaryData;
    };
};

