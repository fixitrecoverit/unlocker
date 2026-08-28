#include "filerestore.h"

std::wstring LowerCopy(std::wstring s)
{
    for (size_t i = 0; i < s.size(); i++)
        s[i] = (wchar_t)towlower(s[i]);
    return s;
}

bool ScanWinSxS(StoreMap& found, const std::vector<std::wstring>& names)
{
    std::wstring sxdir = WinDir() + L"\\WinSxS";
    std::wstring pattern = sxdir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW(pattern.c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE)
        return false;

    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        std::wstring dir = sxdir + L"\\" + fd.cFileName;
        for (size_t i = 0; i < names.size(); i++)
        {
            std::wstring cand = dir + L"\\" + names[i];
            DWORD a = GetFileAttributesW(cand.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY))
                found[LowerCopy(names[i])].push_back(cand);
        }
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
    return true;
}

namespace
{

const struct
{
    const wchar_t* name;
    bool winroot;
} kTargets[] = {
    { L"explorer.exe", true },   { L"cmd.exe", false },
    { L"sethc.exe", false },     { L"utilman.exe", false },
    { L"Narrator.exe", false },  { L"displayswitch.exe", false },
    { L"atbroker.exe", false },  { L"taskmgr.exe", false },
    { L"regedit.exe", true },    { L"wscript.exe", false },
    { L"rundll32.exe", false },  { L"winver.exe", false },
    { L"control.exe", false },
};

ULONGLONG HashFile(const std::wstring& path, bool* ok)
{
    *ok = false;
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ |
                               FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    ULONGLONG h = 14695981039346656037ULL;
    BYTE buf[65536];
    DWORD got = 0;
    for (;;)
    {
        if (!ReadFile(f, buf, sizeof(buf), &got, NULL) || got == 0)
            break;
        for (DWORD i = 0; i < got; i++)
        {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
    }
    CloseHandle(f);
    *ok = true;
    return h;
}

bool GetFileSize2(const std::wstring& path, ULONGLONG* size)
{
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa))
        return false;
    *size = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    return true;
}

void ParseVersionFromDir(const std::wstring& path, ULONGLONG* ver)
{
    *ver = 0;
    size_t slash = path.find_last_of(L"\\/");
    std::wstring dir = (slash == std::wstring::npos) ? path : path.substr(slash + 1);

    size_t pos = 0;
    while (pos < dir.size())
    {
        size_t us = dir.find(L'_', pos);
        std::wstring tok = dir.substr(pos, (us == std::wstring::npos ? dir.size() : us) - pos);
        int a, b, c, d;
        if (swscanf(tok.c_str(), L"%d.%d.%d.%d", &a, &b, &c, &d) == 4)
        {
            *ver = ((ULONGLONG)(ULONG)a << 48) | ((ULONGLONG)(ULONG)b << 32) |
                   ((ULONGLONG)(ULONG)c << 16) | (ULONGLONG)(ULONG)d;
            return;
        }
        if (us == std::wstring::npos)
            break;
        pos = us + 1;
    }
}

std::wstring PickBest(const std::vector<std::wstring>& cands, bool x64File)
{
    const wchar_t* wantTag = x64File ? L"amd64_" : L"x86_";
    std::wstring best;
    ULONGLONG bestVer = 0;
    for (size_t i = 0; i < cands.size(); i++)
    {
        size_t slash = cands[i].find_last_of(L"\\/");
        std::wstring dirpart = cands[i].substr(0, slash);
        std::wstring lowdir = LowerCopy(dirpart.substr(
            dirpart.find_last_of(L"\\/") + 1));

        bool archOk = true;
        if (lowdir.compare(0, 6, L"amd64_") == 0)
            archOk = x64File;
        else if (lowdir.compare(0, 4, L"x86_") == 0)
            archOk = !x64File;

        if (!archOk && cands.size() > 1)
            continue;

        ULONGLONG v = 0;
        ParseVersionFromDir(cands[i], &v);
        bool tagMatch = lowdir.compare(0, wcslen(wantTag), wantTag) == 0;
        ULONGLONG score = v + (tagMatch ? 1ULL << 60 : 0);
        if (score >= bestVer)
        {
            bestVer = score;
            best = cands[i];
        }
    }
    if (best.empty() && !cands.empty())
        best = cands.back();
    return best;
}

bool ReplaceSystemFile(const std::wstring& target, const std::wstring& source,
                       bool* inUse)
{
    *inUse = false;
    EnablePrivByName(SE_TAKE_OWNERSHIP_NAME);
    EnablePrivByName(SE_RESTORE_NAME);
    EnablePrivByName(SE_BACKUP_NAME);

    std::wstring bak = target + L".firi-bak";
    if (GetFileAttributesW(bak.c_str()) == INVALID_FILE_ATTRIBUTES)
        CopyFileW(target.c_str(), bak.c_str(), TRUE);

    std::wstring oldName = target + L".firi-old";
    DeleteFileW(oldName.c_str());
    if (!MoveFileExW(target.c_str(), oldName.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        DWORD e = GetLastError();
        *inUse = e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION;
        return false;
    }
    if (!CopyFileW(source.c_str(), target.c_str(), FALSE))
    {
        MoveFileExW(oldName.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING);
        return false;
    }
    MoveFileExW(oldName.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    return true;
}

}

void CmdFileRestore()
{
    Out(L"scanning winsxs store (slow first time)...\n");

    std::vector<std::wstring> names;
    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++)
        names.push_back(kTargets[i].name);

    StoreMap store;
    if (!ScanWinSxS(store, names))
        Out(L"%s[!]%s can't open %s\\WinSxS - offline image?\n",
            col::Red, col::R, WinDir().c_str());

    bool sysX64 = sizeof(void*) == 8;

    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++)
    {
        std::wstring name = kTargets[i].name;
        std::wstring base = kTargets[i].winroot ? WinDir() : SysDir();
        std::wstring cur = base + L"\\" + name;
        DWORD attrs = GetFileAttributesW(cur.c_str());

        StoreMap::const_iterator it = store.find(LowerCopy(name));
        if (it == store.end() || it->second.empty())
        {
            if (attrs != INVALID_FILE_ATTRIBUTES)
                Out(L" %-18s %sno clean copy in store%s\n",
                    name.c_str(), col::Dim, col::R);
            else
                Out(L" %-18s %smissing, no source%s\n",
                    name.c_str(), col::Red, col::R);
            continue;
        }

        std::wstring src = PickBest(it->second, sysX64);

        if (attrs == INVALID_FILE_ATTRIBUTES)
        {
            Out(L" %-18s %sMISSING%s <- restore from %s? ",
                name.c_str(), col::Red, col::R, src.c_str());
            if (!AskYN(L""))
                continue;
            CopyFileW(src.c_str(), cur.c_str(), FALSE);
            Out(L"%s[+]%s restored\n", col::Grn, col::R);
            continue;
        }

        bool okA = false, okB = false;
        ULONGLONG hs = HashFile(cur, &okA);
        ULONGLONG hd = HashFile(src, &okB);
        ULONGLONG szc = 0, szs = 0;
        GetFileSize2(cur, &szc);
        GetFileSize2(src, &szs);

        if (okA && okB && hs == hd)
        {
            Out(L" %-18s %sok%s (%zu kb)\n", name.c_str(),
                col::Dim, col::R, (size_t)(szc / 1024));
            continue;
        }

        Out(L" %-18s %sMODIFIED%s (%zu kb vs %zu kb)\n",
            name.c_str(), col::Yel, col::R,
            (size_t)(szc / 1024), (size_t)(szs / 1024));

        if (!AskYN(L"replace with store copy?"))
            continue;

        bool inUse = false;
        if (ReplaceSystemFile(cur, src, &inUse))
            Out(L"%s[+]%s replaced (backup: .firi-bak)\n", col::Grn, col::R);
        else if (inUse)
            Out(L"%s[!]%s file locked - try from winpe/safe mode\n",
                col::Yel, col::R);
        else
            LastErr(L"replace");
    }
}

