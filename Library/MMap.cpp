#include "MMap.h"
#include <array>
#include <Windows.h>

static const inline bool isCorrectTargetArchitecture(HANDLE process)
{
    BOOL target = FALSE;
    if (!IsWow64Process(process, &target))
    {
        std::throw_with_nested(std::runtime_error("Error: Wrong platform: " + GetLastError()));
    }

    BOOL host = FALSE;
    IsWow64Process(GetCurrentProcess(), &host);
    return (target == host);
}

MMap::MMap(ProcessInfo processInfo, std::vector<std::byte> _file) :
    process{ OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processInfo.pid) },
    thread{ OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, processInfo.tid) },
    file{ _file }, srcData{ file.data() }
{
    if (!process)
    {
        std::throw_with_nested(std::runtime_error("Error: Failed to open process: " + GetLastError()));
    }

    if (!thread)
    {
        std::throw_with_nested(std::runtime_error("Error: Failed to open thread: " + GetLastError()));
    }

    if (!isCorrectTargetArchitecture(process))
    {
        std::throw_with_nested(std::runtime_error("Error: Target process architecture doesn't match!"));
    }

    const auto oldNtHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(srcData + reinterpret_cast<IMAGE_DOS_HEADER*>(srcData)->e_lfanew) };
    const auto oldOptHeader{ &oldNtHeader->OptionalHeader };
    const auto oldFileHeader{ &oldNtHeader->FileHeader };

    if (oldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::throw_with_nested(std::runtime_error("Invalid architecture: Not a 32bit DLL!"));
    }

    targetBase = reinterpret_cast<std::byte*>(VirtualAllocEx(process, reinterpret_cast<void*>(oldOptHeader->ImageBase), oldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!targetBase)
    {
        targetBase = reinterpret_cast<std::byte*>(VirtualAllocEx(process, nullptr, oldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!targetBase)
        {
            std::throw_with_nested(std::runtime_error("Error: Failed to allocate memory for DLL: " + GetLastError()));
        }
    }

    loader = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!loader)
    {
        VirtualFreeEx(process, targetBase, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: Failed to allocate memory for Loader: " + GetLastError()));
    }

    codeCave = VirtualAllocEx(process, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!codeCave)
    {
        VirtualFreeEx(process, loader, 0, MEM_RELEASE);
        VirtualFreeEx(process, targetBase, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: Failed to allocate memory for CodeCave: " + GetLastError()));
    }
};

template<typename... Ts>
constexpr std::array<std::byte, sizeof...(Ts)> make_bytes(Ts&&... args) {
    return{ std::byte(std::forward<Ts>(args))... };
}

static auto shellcode = make_bytes
(
    0x00, 0x00, 0x00, 0x00,						// - 0x04 (pCodecave)	-> returned value							;buffer to store returned value (eax)

    0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04							;prepare stack for ret
    0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip						;store old eip as return address

    0x50, 0x51, 0x52,							// + 0x0A				-> psuh e(a/c/d)							;save e(a/c/d)x
    0x9C,										// + 0x0D				-> pushfd									;save flags register

    0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0E (+ 0x0F)		-> mov ecx, pArg							;load pArg into ecx
    0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x13 (+ 0x14)		-> mov eax, pRoutine

    0x51,										// + 0x18				-> push ecx									;push pArg
    0xFF, 0xD0,									// + 0x19				-> call eax									;call target function

    0xA3, 0x00, 0x00, 0x00, 0x00,				// + 0x1B (+ 0x1C)		-> mov unsigned long file[pCodecave], eax			;store returned value

    0x9D,										// + 0x20				-> popfd									;restore flags register
    0x5A, 0x59, 0x58,							// + 0x21				-> pop e(d/c/a)								;restore e(d/c/a)x

    0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x24 (+ 0x26)		-> mov byte file[pCodecave + 0x06], 0x00		;set checkbyte to 0

    0xC3										// + 0x2B				-> ret										;return to OldEip
); // SIZE = 0x2C (+ 0x04)

template<typename T>
constexpr auto RELOC_FLAG(T RelInfo) { return ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW); }

static constexpr void __stdcall mapper(MANUAL_MAPPING_DATA* data)
{
    if (!data)
        return;

    const auto base{ reinterpret_cast<std::byte*>(data) };
    const auto opt{ &reinterpret_cast<IMAGE_NT_HEADERS*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(data)->e_lfanew)->OptionalHeader };

    const auto _LoadLibraryA{ data->LoadLibraryA };
    if (!_LoadLibraryA) {
        return;
    }

    const auto _GetProcAddress{ data->GetProcAddress };
    if (!_GetProcAddress) {
        return;
    }

    const auto _dllMain{ reinterpret_cast<_DLL_ENTRY_POINT>(base + opt->AddressOfEntryPoint) };

    const auto locationDelta{ base - opt->ImageBase };
    if (locationDelta)
    {
        if (!opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            return;

        auto relocData{ reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) };

        while (relocData->VirtualAddress)
        {
            auto amountOfEntries{ (relocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short) };
            auto relativeInfo{ reinterpret_cast<unsigned short*>(relocData + 1) };

            for (unsigned int i = 0; i != amountOfEntries; ++i, ++relativeInfo)
            {
                if (RELOC_FLAG(*relativeInfo))
                {
                    auto patch{ reinterpret_cast<uintptr_t*>(base + relocData->VirtualAddress + ((*relativeInfo) & 0xFFF)) };
                    *patch += reinterpret_cast<uintptr_t>(locationDelta);
                }
            }
            relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::byte*>(relocData) + relocData->SizeOfBlock);
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto importDescr{ reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) };
        while (importDescr->Characteristics)
        {
            const char* module{ reinterpret_cast<char*>(base + importDescr->Name) };
            const auto dll{ _LoadLibraryA(module) };

            auto thunkRef{ reinterpret_cast<uintptr_t*>(base + importDescr->OriginalFirstThunk) };
            auto funcRef{ reinterpret_cast<FARPROC*>(base + importDescr->FirstThunk) };

            if (!thunkRef)
                thunkRef = reinterpret_cast<uintptr_t*>(funcRef);

            while (*thunkRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
                {
                    *funcRef = _GetProcAddress(dll, reinterpret_cast<char*>(*thunkRef & 0xFFFF));
                }
                else
                {
                    const auto import{ reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*thunkRef)) };
                    *funcRef = _GetProcAddress(dll, import->Name);
                }
                ++thunkRef;
                ++funcRef;
            }
            ++importDescr;
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        const auto tls{ reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };
        auto callback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks) };
        while (callback && *callback)
            (*callback++)(base, DLL_PROCESS_ATTACH, nullptr);
    }
    _dllMain(base, DLL_PROCESS_ATTACH, nullptr);

    for (unsigned int i = 0; i != 0x1000; i += sizeof(unsigned long))
        *reinterpret_cast<unsigned long*>(base + i) = 0;
}


bool MMap::threadHijack()
{
    CONTEXT ctx = { CONTEXT_FULL };

    if (!thread)
    {
        std::throw_with_nested(std::runtime_error("Error: Wrong thread handle: " + GetLastError()));
    }


    SuspendThread(thread);
    GetThreadContext(thread, &ctx);


    constexpr unsigned long funcOffset = 0x04;
    constexpr unsigned long checkByteOffset = 0x02 + funcOffset;

    *reinterpret_cast<unsigned long*>(shellcode.data() + 0x06 + funcOffset) = ctx.Eip;

    *reinterpret_cast<void**>(shellcode.data() + 0x0F + funcOffset) = targetBase;
    *reinterpret_cast<void**>(shellcode.data() + 0x14 + funcOffset) = loader;

    *reinterpret_cast<void**>(shellcode.data() + 0x1C + funcOffset) = codeCave;
    *reinterpret_cast<std::byte**>(shellcode.data() + 0x26 + funcOffset) = reinterpret_cast<std::byte*>(codeCave) + checkByteOffset;

    ctx.Eip = reinterpret_cast<unsigned long>(codeCave) + funcOffset;

    if (!WriteProcessMemory(process, codeCave, shellcode.data(), shellcode.size(), nullptr)) // + 0x4 because a unsigned long is 0x4 big
    {
        ResumeThread(thread);
        CloseHandle(thread);
        VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: shellcode injection failed: " + GetLastError()));
    }

    if (!SetThreadContext(thread, &ctx))
    {
        ResumeThread(thread);
        CloseHandle(thread);
        VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: Hijacking failed: " + GetLastError()));
    }

    if (ResumeThread(thread) == (unsigned long)-1)
    {
        CloseHandle(thread);
        VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: Failed to resume thread: " + GetLastError()));
    }

    CloseHandle(thread);

    const auto timer{ GetTickCount64() };
    unsigned char checkByte{ 1 };

    do
    {
        ReadProcessMemory(process, reinterpret_cast<std::byte*>(codeCave) + checkByteOffset, &checkByte, 1, nullptr);

        if (GetTickCount64() - timer > 5000)
        {
            VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
            std::throw_with_nested(std::runtime_error("Error: Hijacking timeout: " + GetLastError()));
        }

        Sleep(10);
    } while (checkByte);

    ReadProcessMemory(process, codeCave, &checkByte, sizeof(checkByte), nullptr);
    VirtualFreeEx(process, codeCave, 0, MEM_RELEASE);
    return true;
}

bool MMap::run()
{
    const auto oldNtHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(srcData + reinterpret_cast<IMAGE_DOS_HEADER*>(srcData)->e_lfanew) };
    const auto oldOptHeader{ &oldNtHeader->OptionalHeader };
    const auto oldFileHeader{ &oldNtHeader->FileHeader };

    auto sectionHeader = IMAGE_FIRST_SECTION(oldNtHeader);
    for (unsigned short i = 0; i != oldFileHeader->NumberOfSections; ++i, ++sectionHeader)
    {
        if (sectionHeader->SizeOfRawData)
        {
            if (!WriteProcessMemory(process, targetBase + sectionHeader->VirtualAddress, srcData + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, nullptr))
            {
                VirtualFreeEx(process, targetBase, 0, MEM_RELEASE);
                std::throw_with_nested(std::runtime_error("Error: MMAP failed: " + GetLastError()));
            }
        }
    }

    WriteProcessMemory(process, targetBase, srcData, 0x1000, nullptr);
    WriteProcessMemory(process, targetBase, &data, sizeof(data), nullptr);
    WriteProcessMemory(process, loader, mapper, 0x1000, nullptr);

    uintptr_t dllOut = 0;

    if (!threadHijack())
    {
        VirtualFreeEx(process, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(process, loader, 0, MEM_RELEASE);
        std::throw_with_nested(std::runtime_error("Error: Thread hijacking was not success: " + GetLastError()));
    }

    VirtualFreeEx(process, loader, 0, MEM_RELEASE);

    return true;
}
