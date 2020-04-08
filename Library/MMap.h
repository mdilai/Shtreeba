#pragma once

#include "ProcessInfo.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <stdexcept>

using _LoadLibraryA = HMODULE(__stdcall*)(const char*);
using _GetProcAddress = FARPROC(__stdcall*)(HMODULE, const char*);
using _DLL_ENTRY_POINT = BOOL(__stdcall*)(void* dll, unsigned long reason, void* reserved);

struct MANUAL_MAPPING_DATA
{
    _LoadLibraryA		LoadLibraryA;
    _GetProcAddress	GetProcAddress;
};

class MMap
{
    MANUAL_MAPPING_DATA data{ LoadLibraryA, GetProcAddress };
    HANDLE process{ nullptr };
    HANDLE thread{ nullptr };

    std::vector<std::byte> file;
    std::byte* srcData{ nullptr };
    std::byte* targetBase{ nullptr };
    void* loader{ nullptr };
    void* codeCave{ nullptr };

    bool threadHijack();

public:
    explicit MMap(ProcessInfo processInfo, std::vector<std::byte> _file);

    bool run();

    ~MMap()
    {
        if (thread)
            CloseHandle(thread);
        if (codeCave)
            VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
        if (loader)
            VirtualFreeEx(process, loader, 0, MEM_RELEASE);
        if (process)
            CloseHandle(process);
    }
};