#pragma once
#include "common.h"

struct ProcEntry
{
    DWORD pid;
    DWORD ppid;
    bool suspended;
    std::wstring name;
    std::wstring path;
};

std::vector<ProcEntry> ListProcesses();
void CmdPs(bool live);
void CmdTree();
bool KillPid(DWORD pid, bool verbose = true);
size_t KillByName(const std::wstring& target, bool verbose = true);
