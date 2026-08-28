#include "efi.h"
#include "sig.h"

namespace
{

struct EfiFile
{
    std::wstring path;
    unsigned long long size;
    FILETIME ft;
    int sig;
};

bool HasExt(const std::wstring& name, const wchar_t* ext)
{
    return name.size() >= wcslen(ext) &&
           name.compare(name.size() - wcslen(ext), wcslen(ext), ext) == 0;
}

bool IsEfiInterest(const std::wstring& name)
{
    return HasExt(name, L".efi") || HasExt(name, L".bin") ||
           HasExt(name, L".dll") || HasExt(name, L".pem") ||
           HasExt(name, L".cer");
}

void WalkEfi(const std::wstring& dir, int depth, std::vector<EfiFile>& out)
{
    if (depth > 5 || out.size() > 500)
        return;

    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0)
            continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            WalkEfi(full, depth + 1, out);
            continue;
        }
        std::wstring low = Lower(fd.cFileName);
        if (!IsEfiInterest(low))
            continue;
        EfiFile e;
        e.path = full;
        e.size = ((unsigned long long)fd.nFileSizeHigh << 32) |
                 fd.nFileSizeLow;
        e.ft = fd.ftLastWriteTime;
        e.sig = VerifyFileSig(full);
        out.push_back(e);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
}

std::wstring FtStr(const FILETIME& ft)
{
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    wchar_t b[40];
    swprintf(b, 40, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return b;
}

wchar_t FreeDrive()
{
    DWORD mask = GetLogicalDrives();
    for (wchar_t c = L'Z'; c >= L'D'; c--)
        if (!(mask & (1u << (c - L'A'))))
            return c;
    return L'Z';
}

}

void CmdEfiCheck()
{
    wchar_t vol = FreeDrive();
    std::wstring mount = std::wstring(1, vol) + L":";
    std::wstring cmd = L"/c mountvol " + mount + L" /S";

    SHELLEXECUTEINFOW si;
    memset(&si, 0, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    si.lpVerb = NULL;
    si.lpFile = L"C:\\Windows\\System32\\cmd.exe";
    si.lpParameters = cmd.c_str();
    si.nShow = SW_HIDE;
    if (!ShellExecuteExW(&si) || !si.hProcess)
    {
        LastErr(L"mountvol");
        return;
    }
    WaitForSingleObject(si.hProcess, 15000);
    CloseHandle(si.hProcess);

    DWORD at = GetFileAttributesW((mount + L"\\EFI").c_str());
    if (at == INVALID_FILE_ATTRIBUTES)
    {
        Out(L"%s[!]%s could not access EFI system partition\n", col::Red,
            col::R);
        return;
    }

    Out(L"%sefi system partition%s mounted at %s\n", col::Cyn, col::R,
        mount.c_str());

    std::vector<EfiFile> files;
    WalkEfi(mount + L"\\EFI", 0, files);

    int unsignedCount = 0;
    for (size_t i = 0; i < files.size(); i++)
    {
        const EfiFile& e = files[i];
        const wchar_t* tag;
        const wchar_t* tc;
        if (e.sig == 1)
        {
            tag = L"[signed]";
            tc = col::Dim;
        }
        else if (e.sig == 0)
        {
            tag = L"[UNSIGNED]";
            tc = col::Yel;
            unsignedCount++;
        }
        else
        {
            tag = L"[?]";
            tc = col::Dim;
        }
        Out(L"%s%-11s%s %10llu  %s  %s\n", tc, tag, col::R, e.size,
            FtStr(e.ft).c_str(), e.path.c_str());
    }

    if (files.empty())
        Out(L"%sno efi binaries under \\EFI%s\n", col::Dim, col::R);
    else if (unsignedCount == 0)
        Out(L"%sall %d entries signed%s\n", col::Grn, (int)files.size(),
            col::R);
    else
        Out(L"%s%d of %d UNSIGNED - review paths above%s\n", col::Yel,
            unsignedCount, (int)files.size(), col::R);

    SHELLEXECUTEINFOW si2;
    memset(&si2, 0, sizeof(si2));
    si2.cbSize = sizeof(si2);
    si2.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    si2.lpVerb = NULL;
    si2.lpFile = L"C:\\Windows\\System32\\cmd.exe";
    std::wstring un = L"/c mountvol " + mount + L" /D";
    si2.lpParameters = un.c_str();
    si2.nShow = SW_HIDE;
    if (ShellExecuteExW(&si2) && si2.hProcess)
    {
        WaitForSingleObject(si2.hProcess, 10000);
        CloseHandle(si2.hProcess);
    }
}
