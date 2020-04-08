#include "FindProcessId.h"
#include <memory>
#include <stdexcept>
#include <string>

static std::string errMsg() {
    char* e = strerror(errno);
    return e ? e : "";
}

FindProcessId::FindProcessId() {
    const auto hNTDLL{ LoadLibraryW(L"ntdll") };
    if (!hNTDLL)
        std::throw_with_nested(std::runtime_error("Unable to get handle of ntdll.dll library: " + errMsg()));

    const auto ntQSI{ reinterpret_cast<f_NTQuerySystemInformation>(GetProcAddress(hNTDLL, "NtQuerySystemInformation")) };
    if (!ntQSI)
        std::throw_with_nested(std::runtime_error("Unable to load NTQuerySystemInformation function: " + errMsg()));

    if (SIZE_T buffersize; !NT_SUCCESS(ntQSI(SystemProcessInformation, nullptr, 0, &buffersize))) {
        auto buffer{ std::make_unique<std::byte[]>(buffersize) };
        auto spi{ reinterpret_cast<SYSTEM_PROCESSES*>(buffer.get()) };
        if (NTSTATUS status; !NT_SUCCESS(status = ntQSI(SystemProcessInformation, spi, buffersize, nullptr)))
            std::throw_with_nested(std::runtime_error("Error: Unable to query list of running processes: " + status));

        while (spi->NextEntryDelta)
        {
            spi = reinterpret_cast<SYSTEM_PROCESSES*>((LPBYTE)spi + spi->NextEntryDelta);
            const auto processName{ spi->ProcessName.Buffer };
            const auto pid{ spi->ProcessId };
            const auto tid{ reinterpret_cast<ULONG>(spi->Threads->ClientId.UniqueThread) };
            processList.emplace_back(ProcessInfo{ processName, pid, tid });
        }
    }
}

ProcessInfo FindProcessId::getProcess(std::wstring_view processName)
{
    for (const auto& process : processList)
        if (processName == process.processName)
            return process;

    std::throw_with_nested(std::runtime_error("Error: Failed to find target process!"));
}

ProcessInfo FindProcessId::getProcess(int pid)
{
    for (const auto& process : processList)
        if (pid == process.pid)
            return process;

    std::throw_with_nested(std::runtime_error("Error: Failed to find target process!"));
}