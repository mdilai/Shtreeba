#pragma once
#include <string>

struct ProcessInfo {
    const std::wstring processName;
    const unsigned long pid;
    const unsigned long tid;
};
