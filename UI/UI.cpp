#include "FindProcessId.h"

#include <iostream>
#include <filesystem>
#include <sstream>

#include <Windows.h>

using _Start = bool(*)(ProcessInfo, const std::filesystem::path&);

static const inline int MessageBoxTimeoutW(HWND hWnd, const WCHAR* sText, const WCHAR* sCaption, UINT uType, DWORD dwMilliseconds)
{
    using _MessageBoxTimeoutW = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
    int iResult;
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32)
    {
        const auto MessageBoxTimeoutW{ reinterpret_cast<_MessageBoxTimeoutW>(GetProcAddress(hUser32, "MessageBoxTimeoutW")) };
        iResult = MessageBoxTimeoutW(hWnd, sText, sCaption, uType, 0, dwMilliseconds);
        FreeLibrary(hUser32);
    }
    else
        iResult = MessageBox(hWnd, sText, sCaption, uType);

    return iResult;
}

static const inline void adjustPrivileges()
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid.LowPart = 20; // 20 = SeDebugPrivilege
    tp.Privileges[0].Luid.HighPart = 0;

    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, 0);
        CloseHandle(token);
    }
}

static const inline auto getConfig(LPCWSTR section, LPCWSTR key, LPCWSTR def, LPCWSTR filename)
{
    wchar_t temp[MAX_PATH];
    int result = GetPrivateProfileStringW(section, key, def, temp, sizeof(temp) / sizeof(temp[0]), filename);
    return std::wstring(temp, result);
}

static const inline auto getConfig(LPCWSTR section, LPCWSTR key, int def, LPCWSTR filename)
{
    return GetPrivateProfileIntW(section, key, def, filename);
}

static const inline auto setConfig(LPCWSTR section, LPCWSTR key, LPCWSTR data, LPCWSTR filename)
{
    if (!WritePrivateProfileStringW(section, key, data, filename))
        std::wcout << "Error: Unable to save config file: " << GetLastError() << "\n";
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    constexpr auto libraryName{ L"Shtreeba" };
    const auto configPath{ std::filesystem::absolute(std::filesystem::path(L"Shtreeba.ini")) };

    const auto fileName{ getConfig(L"Library", L"DLL", L"Jweega.bin", configPath.c_str()) };
    const auto processName{ getConfig(L"Library", L"ProcessName", L"csgo.exe", configPath.c_str()) };
    const auto isSilent{ getConfig(L"UI", L"Silent", 0, configPath.c_str()) };
    const auto closeDelay{ getConfig(L"UI", L"CloseDelay", 3000, configPath.c_str()) };
    if (!std::filesystem::exists(configPath)) {
        setConfig(L"Library", L"DLL", fileName.data(), configPath.c_str());
        setConfig(L"Library", L"ProcessName", processName.data(), configPath.c_str());
        setConfig(L"UI", L"Silent", std::to_wstring(isSilent).data(), configPath.c_str());
        setConfig(L"UI", L"CloseDelay", std::to_wstring(closeDelay).data(), configPath.c_str());
    }

    const auto hInst = LoadLibraryW(std::filesystem::absolute(std::filesystem::path(libraryName)).c_str());
    if (!hInst) {
        std::wcout << "Shtreeba.dll loading failed\n";
        MessageBoxW(NULL, L"Shtreeba.dll loading failed", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }


    const auto Shtreeba = reinterpret_cast<_Start>(GetProcAddress(hInst, "Start"));
    if (!Shtreeba) {
        FreeLibrary(hInst);
        std::wcout << "Failed to load function from library\n";
        MessageBoxW(NULL, L"Failed to load function from library", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    try {
        adjustPrivileges();
        FindProcessId processList;
        const auto processInfo{ processList.getProcess(processName) };
        const auto filePath{ std::filesystem::absolute(std::filesystem::path(fileName)) };
        Shtreeba(processInfo, filePath);
        if (!isSilent) {
            std::wcout << "Process name: " << processInfo.processName << "\nPID: " << processInfo.pid << "\nTID: " << processInfo.tid << "\n";
            std::wcout << "Done!" << "\n";
            auto buf{ (std::wstringstream{ } << "Process name: " << processInfo.processName << "\nPID: " << processInfo.pid << "\nTID: " << processInfo.tid << "\n").str() };
            MessageBoxTimeoutW(NULL, buf.data(), L"Success", MB_OK | MB_ICONINFORMATION, closeDelay);
        }
    }
    catch (const std::exception& e) {
        FreeLibrary(hInst);
        std::cerr << e.what() << '\n';
        MessageBoxA(NULL, e.what(), "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    FreeLibrary(hInst);
    return EXIT_SUCCESS;
}