#include "File.h"
#include <fstream>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <Windows.h>

static std::string errMsg() {
    char* e = strerror(errno);
    return e ? e : "";
}

File::File(const std::filesystem::path& filepath) {
    if (!std::filesystem::exists(filepath))
    {
        auto ex{ (std::ostringstream{} << "I/O error: File doesn't exist (" << filepath.string() << ")").str() };
        std::throw_with_nested(std::runtime_error(ex));
    }

    std::basic_ifstream<std::byte> file(filepath, std::ios::binary);
    if (!file)
        std::throw_with_nested(std::runtime_error("I/O error: " + errMsg()));

    file.exceptions(std::ifstream::failbit | std::ifstream::badbit);

    if (std::filesystem::file_size(filepath) < 0x1000)
    {
        auto ex{ (std::ostringstream{} << "I/O error: Invalid filesize (" << filepath.string() << ")").str() };
        std::throw_with_nested(std::runtime_error(ex));
    }

    binaryData = { std::istreambuf_iterator<std::byte>(file), std::istreambuf_iterator<std::byte>() };
    file.close();

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(binaryData.data())->e_magic != 0x5A4D) //"MZ"
    {
        auto ex{ (std::ostringstream{} << "I/O error: Invalid binary file (" << filepath.string() << ")").str() };
        std::throw_with_nested(std::runtime_error(ex));
    }
};