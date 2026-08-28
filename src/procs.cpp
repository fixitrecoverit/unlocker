#include "procs.h"
#include <tlhelp32.h>
#include <map>
#include <set>

typedef struct _FIRI_US
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} FIRI_US;

typedef struct _FIRI_THREAD
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    struct { HANDLE pid; HANDLE tid; } cid;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} FIRI_THREAD;

typedef struct _FIRI_PROC
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    FIRI_US ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} FIRI_PROC;

static const ULONG kStateWaiting = 4;  /* KTHREAD_STATE.Waiting */
static const ULONG kReasonSuspended = 5; /* KWAIT_REASON.Suspended */
static const ULONG kSystemProcessInformation = 5;
static const ULONG kStatusInfoLengthMismatch = 0xC0000004; /* STATUS_INFO_LENGTH_MISMATCH */

#ifdef _WIN64
static_assert(sizeof(FIRI_THREAD) == 0x50, "FIRI_THREAD must match x64 SYSTEM_THREAD_INFORMATION");
static_assert(FIELD_OFFSET(FIRI_THREAD, ThreadState) == 0x44,
              "ThreadState must be at 0x44 (x64 SYSTEM_THREAD_INFORMATION)");
static_assert(FIELD_OFFSET(FIRI_THREAD, WaitReason) == 0x48,
              "WaitReason must be at 0x48 (x64 SYSTEM_THREAD_INFORMATION)");
#else
static_assert(sizeof(FIRI_THREAD) == 0x3C, "FIRI_THREAD must match x86 SYSTEM_THREAD_INFORMATION");
static_assert(FIELD_OFFSET(FIRI_THREAD, ThreadState) == 0x34,
              "ThreadState must be at 0x34 (x86 SYSTEM_THREAD_INFORMATION)");
static_assert(FIELD_OFFSET(FIRI_THREAD, WaitReason) == 0x38,
              "WaitReason must be at 0x38 (x86 SYSTEM_THREAD_INFORMATION)");
#endif

static bool QuerySuspendedMap(std::map<DWORD, bool>& out)
{
    out.clear();
    typedef LONG(NTAPI * FN_NtQsi)(ULONG, PVOID*, ULONG, PULONG);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return false;
    FN_NtQsi q = (FN_NtQsi)(void*)GetProcAddress(nt, "NtQuerySystemInformation");
    if (!q)
        return false;

    ULONG len = 4 * 1024 * 1024;
    for (int attempt = 0; attempt < 3; attempt++)
    {
        std::vector<BYTE> buf(len);
        ULONG need = 0;
        LONG st = q(kSystemProcessInformation, (PVOID*)buf.data(), len, &need);
        if (st == 0)
        {
            BYTE* p = buf.data();
            for (;;)
            {
                FIRI_PROC* pi = (FIRI_PROC*)p;
                DWORD pid = (DWORD)(ULONG_PTR)pi->UniqueProcessId;
                bool all = pi->NumberOfThreads > 0;
                FIRI_THREAD* th = (FIRI_THREAD*)(p + sizeof(FIRI_PROC));
                for (ULONG i = 0; i < pi->NumberOfThreads && all; i++)
                    if (th[i].ThreadState != kStateWaiting ||
                        th[i].WaitReason != kReasonSuspended)
                        all = false;
                if (pid)
                    out[pid] = all;
                if (!pi->NextEntryOffset)
                    break;
                p += pi->NextEntryOffset;
            }
            return true;
        }
        if (st != (LONG)kStatusInfoLengthMismatch)
            return false;
        len = need ? need + (1 << 20) : len * 2;
    }
    return false;
}

namespace
{

const wchar_t* const kCriticalNames[] = {
    L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
    L"services.exe", L"lsass.exe", L"svchost.exe", L"dwm.exe",
    L"fontdrvhost.exe", L"taskhostw.exe",
};

bool IsCritical(const ProcEntry& e)
{
    for (size_t i = 0; i < sizeof(kCriticalNames) / sizeof(kCriticalNames[0]); i++)
        if (_wcsicmp(e.name.c_str(), kCriticalNames[i]) == 0)
            return true;
    return false;
}

bool IsMasquerading(const ProcEntry& e)
{
    if (!IsCritical(e))
        return false;
    if (e.path.empty())
        return false;

    std::wstring sys32 = Lower(SysDir());
    std::wstring wow64 = Lower(WinDir()) + L"\\syswow64\\";
    std::wstring p = Lower(e.path);

    if (p.compare(0, sys32.size(), sys32) == 0)
        return false;
    if (wow64.size() > 2 && p.compare(0, wow64.size(), wow64) == 0)
        return false;
    return true;
}

}

std::vector<ProcEntry> ListProcesses()
{
    std::vector<ProcEntry> out;
    std::map<DWORD, bool> sus;
    QuerySuspendedMap(sus);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        LastErr(L"CreateToolhelp32Snapshot");
        return out;
    }
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            ProcEntry e;
            e.pid = pe.th32ProcessID;
            e.ppid = pe.th32ParentProcessID;
            e.name = pe.szExeFile;
            e.suspended = false;
            std::map<DWORD, bool>::const_iterator it = sus.find(e.pid);
            if (it != sus.end())
                e.suspended = it->second;
            out.push_back(e);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    for (size_t i = 0; i < out.size(); i++)
    {
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, out[i].pid);
        if (p)
        {
            wchar_t b[1024];
            DWORD sz = 1024;
            if (QueryFullProcessImageNameW(p, 0, b, &sz) && sz > 0)
                out[i].path.assign(b, sz);
            CloseHandle(p);
        }
    }
    return out;
}

static void RenderPs()
{
    std::vector<ProcEntry> list = ListProcesses();
    Out(L"%6s %-26s %-16s %s\n", L"PID", L"NAME", L"FLAGS", L"LOCATION");
    for (size_t i = 0; i < list.size(); i++)
    {
        const ProcEntry& e = list[i];
        Out(L"%6lu ", (unsigned long)e.pid);

        std::wstring name = e.name;
        if (name.size() > 26)
            name.resize(26);
        Out(L"%-26s", name.c_str());

        std::wstring f;
        if (e.pid == 4 || IsCritical(e))
            f += L"[crit]";
        if (e.suspended)
            f += L"[sus]";
        if (IsMasquerading(e))
            f += L"[!MASQ]";

        if (f.find(L"[sus]") != std::wstring::npos)
            Out(L"%s%-16s%s", col::Yel, f.c_str(), col::R);
        else if (!f.empty())
            Out(L"%s%-16s%s", col::Red, f.c_str(), col::R);
        else
            Out(L"%-16s", L"");

        Out(L"%s\n",
            e.path.empty() ? e.name.c_str() : e.path.c_str());
    }
    Out(L"%s%zu processes. [crit]=system [sus]=frozen [!MASQ]=fake system name%s\n",
        col::Dim, list.size(), col::R);
}

void CmdPs(bool live)
{
    if (!live || !StdoutIsConsole())
    {
        RenderPs();
        return;
    }

    Out(L"%s[esc/q] stop%s\n", col::Dim, col::R);
    for (;;)
    {
        ClrScr();
        RenderPs();

        Sleep(1000);

        bool quit = false;
        INPUT_RECORD rec[16];
        DWORD n = 0;
        while (PeekConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), rec, 16, &n) && n)
        {
            DWORD read = 0;
            ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), rec, 16, &read);
            for (DWORD i = 0; i < read; i++)
                if (rec[i].EventType == KEY_EVENT && rec[i].Event.KeyEvent.bKeyDown)
                {
                    WORD vk = rec[i].Event.KeyEvent.wVirtualKeyCode;
                    wchar_t ch = rec[i].Event.KeyEvent.uChar.AsciiChar;
                    if (vk == VK_ESCAPE || ch == L'q' || ch == L'Q')
                        quit = true;
                }
        }
        if (quit)
            break;
    }
}

bool KillPid(DWORD pid, bool verbose)
{
    if (pid <= 4)
    {
        Out(L"%s[!]%s not killing system pid %lu\n", col::Red, col::R,
            (unsigned long)pid);
        return false;
    }
    if (pid == GetCurrentProcessId())
    {
        Out(L"%s[!]%s that's me\n", col::Red, col::R);
        return false;
    }
    HANDLE p = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION |
                               SYNCHRONIZE,
                           FALSE, pid);
    if (!p)
    {
        LastErr(L"OpenProcess");
        return false;
    }
    wchar_t name[1024] = L"?";
    DWORD sz = 1024;
    QueryFullProcessImageNameW(p, 0, name, &sz);
    if (!TerminateProcess(p, (UINT)-2))
    {
        LastErr(L"TerminateProcess");
        CloseHandle(p);
        return false;
    }
    WaitForSingleObject(p, 5000);
    CloseHandle(p);
    if (verbose)
        Out(L"%s[+]%s killed %lu (%s)\n", col::Grn, col::R,
            (unsigned long)pid, name);
    return true;
}

size_t KillByName(const std::wstring& target, bool verbose)
{
    std::wstring want = Lower(target);
    size_t killed = 0;
    std::vector<ProcEntry> list = ListProcesses();
    for (size_t i = 0; i < list.size(); i++)
    {
        std::wstring leaf = Lower(list[i].name);
        const std::wstring& pf = list[i].path;
        size_t slash = pf.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < pf.size())
            leaf = Lower(pf.substr(slash + 1));
        if (leaf == want)
        {
            if (KillPid(list[i].pid, verbose))
                killed++;
        }
    }
    if (!killed && verbose)
        Out(L"%s[!]%s nothing matches '%s'\n", col::Red, col::R, target.c_str());
    return killed;
}

namespace
{

void TreeWalk(const std::vector<ProcEntry>& list,
              const std::multimap<DWORD, size_t>& kids, DWORD pid,
              const std::wstring& pre, std::set<DWORD>& visited, int depth)
{
    if (depth > 14 || visited.count(pid))
        return;
    visited.insert(pid);

    std::vector<size_t> ch;
    std::pair<std::multimap<DWORD, size_t>::const_iterator,
              std::multimap<DWORD, size_t>::const_iterator> range =
        kids.equal_range(pid);
    for (std::multimap<DWORD, size_t>::const_iterator it = range.first;
         it != range.second; ++it)
        ch.push_back(it->second);

    for (size_t a = 0; a + 1 < ch.size(); a++)
        for (size_t b2 = a + 1; b2 < ch.size(); b2++)
            if (Lower(list[ch[b2]].name) < Lower(list[ch[a]].name))
                std::swap(ch[a], ch[b2]);

    for (size_t i = 0; i < ch.size(); i++)
    {
        const ProcEntry& e = list[ch[i]];
        bool lastOne = i + 1 == ch.size();

        std::wstring f;
        if (e.suspended)
            f += L"[sus]";
        if (IsMasquerading(e))
            f += L"[!MASQ]";
        else if (IsCritical(e))
            f += L"[crit]";

        Out(L"%s%s%s%s %s (%lu)%s %s\n", pre.c_str(),
            lastOne ? L"\x2514\x2500 " : L"\x251c\x2500 ",
            f.empty() ? L"" : col::Red, f.c_str(), e.name.c_str(),
            (unsigned long)e.pid, f.empty() ? L"" : col::R,
            e.suspended ? L"frozen" : L"");
    TreeWalk(list, kids, e.pid,
             pre + (lastOne ? L"   " : L"\x2502  "), visited, depth + 1);
    }
}

}

void CmdTree()
{
    std::vector<ProcEntry> list = ListProcesses();
    if (list.empty())
        return;

    std::map<DWORD, size_t> idx;
    std::multimap<DWORD, size_t> kids;
    for (size_t i = 0; i < list.size(); i++)
    {
        idx[list[i].pid] = i;
        if (list[i].ppid != list[i].pid)
            kids.insert(std::make_pair(list[i].ppid, i));
    }

    Out(L"%sprocess tree%s (%d)\n", col::Cyn, col::R, (int)list.size());

    std::set<DWORD> visited;
    std::vector<size_t> roots;
    for (size_t i = 0; i < list.size(); i++)
    {
        const ProcEntry& e = list[i];
        if (e.pid == 0 || !idx.count(e.ppid))
            roots.push_back(i);
    }

    for (size_t i = 0; i < roots.size(); i++)
    {
        const ProcEntry& r = list[roots[i]];
        bool orphan = r.ppid != 0;
        Out(L"%s%s %s (%lu)%s\n", orphan ? col::Yel : L"",
            orphan ? L"[orphan]" : L"", r.name.c_str(),
            (unsigned long)r.pid, orphan ? col::R : L"");
        TreeWalk(list, kids, r.pid, orphan ? L"   " : L"", visited, 0);
    }
}
