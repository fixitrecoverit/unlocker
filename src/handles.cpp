#include "handles.h"
#include "procs.h"
#include <map>
#include <set>

namespace
{

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT ObjectTypeIndex;
    UCHAR HandleAttributes;
    UCHAR GrantedAccess;
    USHORT HandleValue;
} SHTEI;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SHTEI Handles[1];
} SHI;

typedef LONG(NTAPI* FN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* FN_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct UNICODE_STRING_W
{
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
};

struct NameJob
{
    FN_NtQueryObject fn;
    HANDLE handle;
    BYTE buf[2048];
    ULONG need;
    LONG status;
    bool finished;
};

DWORD WINAPI NameThread(LPVOID p)
{
    NameJob* j = (NameJob*)p;
    j->status = j->fn(j->handle, 1, j->buf, sizeof(j->buf), &j->need);
    j->finished = true;
    return 0;
}

std::wstring ObjectName(HANDLE dup, FN_NtQueryObject fn)
{
    NameJob job;
    memset(&job, 0, sizeof(job));
    job.fn = fn;
    job.handle = dup;

    HANDLE t = CreateThread(NULL, 0, NameThread, &job, 0, NULL);
    if (!t)
        return std::wstring();

    DWORD w = WaitForSingleObject(t, 150);
    if (w != WAIT_OBJECT_0)
    {
        CloseHandle(t);
        return std::wstring();
    }
    CloseHandle(t);
    if (!job.finished || job.status != 0)
        return std::wstring();

    UNICODE_STRING_W* us = (UNICODE_STRING_W*)job.buf;
    if (!us->Buffer || us->Length == 0 || us->Length > 1024)
        return std::wstring();
    return std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
}

std::map<std::wstring, std::wstring> BuildDeviceMap()
{
    std::map<std::wstring, std::wstring> m;
    for (wchar_t d = L'A'; d <= L'Z'; d++)
    {
        wchar_t letter[3] = {d, L':', 0};
        wchar_t dev[512];
        if (QueryDosDeviceW(letter, dev, 512))
        {
            std::wstring dd(dev);
            if (!dd.empty())
                m[Lower(dd)] = std::wstring(1, d) + L":";
        }
    }
    return m;
}

std::wstring DeviceToDos(const std::wstring& name,
                         const std::map<std::wstring, std::wstring>& dm)
{
    std::wstring low = Lower(name);
    for (std::map<std::wstring, std::wstring>::const_iterator it = dm.begin();
         it != dm.end(); ++it)
    {
        if (low.compare(0, it->first.size(), it->first) == 0)
            return it->second + name.substr(it->first.size());
    }
    return std::wstring();
}

} 

void CmdHandles(const std::wstring& targetIn)
{
    if (targetIn.empty())
    {
        Out(L"[!] usage: handles <file-or-folder>\n");
        return;
    }

    wchar_t abs[1024];
    if (!GetFullPathNameW(targetIn.c_str(), 1024, abs, NULL))
        return;
    std::wstring target = Lower(std::wstring(abs));
    bool isDir = false;
    DWORD at = GetFileAttributesW(abs);
    if (at == INVALID_FILE_ATTRIBUTES)
    {
        Out(L"[!] path not found: %s\n", abs);
        return;
    }
    isDir = (at & FILE_ATTRIBUTE_DIRECTORY) != 0;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return;
    FN_NtQuerySystemInformation qsi =
        (FN_NtQuerySystemInformation)GetProcAddress(nt,
                                                    "NtQuerySystemInformation");
    FN_NtQueryObject nqo =
        (FN_NtQueryObject)GetProcAddress(nt, "NtQueryObject");
    if (!qsi || !nqo)
        return;

    std::vector<ProcEntry> procs = ListProcesses();
    std::map<DWORD, std::wstring> names;
    for (size_t i = 0; i < procs.size(); i++)
        names[procs[i].pid] = procs[i].name;

    Out(L"scanning handles for %s%s%s...\n", col::Cyn, abs, col::R);

    std::vector<BYTE> info(1 << 20);
    ULONG need = 0;
    LONG st = 0;
    for (;;)
    {
        st = qsi(16, info.data(), (ULONG)info.size(), &need);
        if (st == 0)
            break;
        if (need == 0 || need > (64u << 20))
        {
            Out(L"%s[!]%s handle query failed\n", col::Red, col::R);
            return;
        }
        info.resize(need + (1 << 16));
    }

    SHI* hi = (SHI*)info.data();
    std::map<std::wstring, std::wstring> dm = BuildDeviceMap();

    struct Holder
    {
        DWORD pid;
        std::wstring name;
    };
    std::vector<Holder> found;
    std::set<DWORD> seenPid;

    for (ULONG i = 0; i < hi->NumberOfHandles; i++)
    {
        const SHTEI& h = hi->Handles[i];
        DWORD pid = h.UniqueProcessId;
        if (pid == GetCurrentProcessId() || !names.count(pid))
            continue;
        if (seenPid.count(pid))
            continue;

        HANDLE p = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (!p)
            continue;
        HANDLE dup = NULL;
        BOOL ok = DuplicateHandle(p, (HANDLE)(ULONG_PTR)h.HandleValue,
                                  GetCurrentProcess(), &dup, 0, FALSE,
                                  DUPLICATE_SAME_ACCESS);
        CloseHandle(p);
        if (!ok || !dup)
            continue;

        bool match = false;
        if (GetFileType(dup) == FILE_TYPE_DISK)
        {
            std::wstring nm = ObjectName(dup, nqo);
            if (!nm.empty())
            {
                std::wstring dos = DeviceToDos(nm, dm);
                if (!dos.empty())
                {
                    std::wstring dl = Lower(dos);
                    if (isDir)
                        match = dl.compare(0, target.size(), target) == 0;
                    else
                        match = dl == target;
                }
            }
        }
        CloseHandle(dup);

        if (match)
        {
            seenPid.insert(pid);
            Holder hd;
            hd.pid = pid;
            hd.name = names[pid];
            found.push_back(hd);
            Out(L"  %s%-6lu%s %s\n", col::Cyn, (unsigned long)pid, col::R,
                hd.name.c_str());
        }
    }

    if (found.empty())
        Out(L"%sno process holds a handle to it%s\n", col::Dim, col::R);
    else
        Out(L"%s%d holder(s)%s\n", col::Cyn, (int)found.size(), col::R);
}

