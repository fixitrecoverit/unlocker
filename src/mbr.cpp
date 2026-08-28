#include "mbr.h"

namespace
{

constexpr unsigned long long NOSIZE = ~0ull;

struct Sig
{
    const wchar_t* name;
    const wchar_t* bootloader;
    const wchar_t* os;
    unsigned long long sizeMin;
    unsigned long long sizeMax;
};

const Sig kSigs[] = {
    { L"bootmgfw.efi", L"windows boot manager", L"windows", 1200000, 3100000 },
    { L"winload.efi", L"windows", L"windows", 700000, 2500000 },
    { L"winload.exe", L"windows", L"windows", 700000, 2500000 },
    { L"winresume.efi", L"windows", L"windows", NOSIZE, 0 },
    { L"winresume.exe", L"windows", L"windows", NOSIZE, 0 },
    { L"bootmgr.efi", L"windows boot manager", L"windows", NOSIZE, 0 },
    { L"bootmgr", L"windows boot manager", L"windows", 300000, 1300000 },
    { L"grubx64.efi", L"grub", L"unknown distro", 900000, 7000000 },
    { L"grubia32.efi", L"grub", L"unknown distro", 800000, 5000000 },
    { L"grub.efi", L"grub", L"unknown distro", 800000, 6000000 },
    { L"shimx64.efi", L"shim", L"unknown distro", 80000, 1600000 },
    { L"shim.efi", L"shim", L"unknown distro", 80000, 1600000 },
    { L"core.img", L"grub (bios)", L"unknown distro", NOSIZE, 0 },
    { L"grub", L"grub", L"unknown distro", NOSIZE, 0 },
    { L"vmlinuz-linux-cachyos", L"cachyos kernel", L"cachyos", NOSIZE, 0 },
    { L"initramfs-linux-cachyos.img", L"cachyos", L"cachyos", NOSIZE, 0 },
    { L"vmlinuz-linux-lts", L"arch kernel", L"arch", NOSIZE, 0 },
    { L"initramfs-linux-lts.img", L"arch", L"arch", NOSIZE, 0 },
    { L"vmlinuz-linux", L"arch kernel", L"arch", NOSIZE, 0 },
    { L"initramfs-linux.img", L"arch", L"arch", NOSIZE, 0 },
    { L"vmlinuz", L"linux kernel", L"unknown distro", NOSIZE, 0 },
    { L"initramfs.img", L"linux", L"unknown distro", NOSIZE, 0 },
    { L"systemd-bootx64.efi", L"systemd-boot", L"arch/systemd distro", 90000, 400000 },
    { L"systemd-bootia32.efi", L"systemd-boot", L"arch/systemd distro", 90000, 400000 },
    { L"EFI\\Microsoft", L"windows boot", L"windows", NOSIZE, 0 },
    { L"EFI\\ubuntu", L"grub", L"ubuntu", NOSIZE, 0 },
    { L"EFI\\debian", L"grub", L"debian", NOSIZE, 0 },
    { L"EFI\\arch", L"grub/systemd-boot", L"arch", NOSIZE, 0 },
    { L"EFI\\cachyos", L"grub/systemd-boot", L"cachyos", NOSIZE, 0 },
};

const wchar_t* ExeTail(const wchar_t* s)
{
    const wchar_t* p = s;
    for (; *s; s++)
        if (*s == L'\\' || *s == L'/')
            p = s + 1;
    return p;
}

const wchar_t* SizeTag(const Sig& s, unsigned long long sz)
{
    if (s.sizeMin == NOSIZE)
        return L"";
    return (sz >= s.sizeMin && sz <= s.sizeMax) ? L" [size ok]"
                                                : L" [size MISMATCH]";
}

void Walk(const std::wstring& dir, int depth, std::vector<std::wstring>& files,
          std::vector<std::wstring>& grubCfgs)
{
    if (depth > 6)
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
            Walk(full, depth + 1, files, grubCfgs);
            continue;
        }
        files.push_back(full);
        if (wcscmp(fd.cFileName, L"grub.cfg") == 0)
            grubCfgs.push_back(full);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
}

bool HasGrubSig(const Sig* s)
{
    if (!s)
        return false;
    return wcsstr(s->bootloader, L"grub") != NULL ||
           wcsstr(s->bootloader, L"shim") != NULL ||
           wcsstr(s->os, L"grub") != NULL;
}

bool SkipTitle(const std::wstring& t)
{
    std::wstring lo = Lower(t);
    return lo.find(L"advanced options") != std::wstring::npos ||
           lo.find(L"recovery") != std::wstring::npos ||
           lo.find(L"memtest") != std::wstring::npos ||
           lo.find(L"upstart") != std::wstring::npos ||
           lo.find(L"previous linux") != std::wstring::npos;
}

std::wstring EntryTitle(const std::wstring& line)
{
    size_t pos = line.find_first_of(L"\"'");
    if (pos == std::wstring::npos)
        return L"";
    wchar_t q = line[pos];
    size_t end = line.find(q, pos + 1);
    if (end == std::wstring::npos)
        return L"";
    return line.substr(pos + 1, end - pos - 1);
}

void ParseGrubConfig(const std::wstring& path,
                     std::vector<std::wstring>& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (8 << 20))
    {
        CloseHandle(h);
        return;
    }
    std::vector<char> raw((size_t)sz.QuadPart + 1);
    DWORD rd = 0;
    if (!ReadFile(h, raw.data(), (DWORD)sz.QuadPart, &rd, NULL))
    {
        CloseHandle(h);
        return;
    }
    CloseHandle(h);
    raw[rd] = 0;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, raw.data(), (int)rd, NULL, 0);
    if (wlen <= 0)
    {
        wlen = MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)rd, NULL, 0);
        if (wlen <= 0)
            return;
    }
    std::wstring text((size_t)wlen, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, raw.data(), (int)rd, &text[0],
                            wlen) == 0 &&
        MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)rd, &text[0],
                            wlen) == 0)
        return;
    std::vector<std::wstring> lines;
    SplitLines(text, lines);

    std::vector<int> subStack;
    int depth = 0;
    bool suppressed = false;

    for (size_t i = 0; i < lines.size(); i++)
    {
        std::wstring t = Trim(lines[i].c_str());
        if (t.empty())
            continue;
        std::wstring low = Lower(t);

        size_t braceRange = t.find_first_of(L"{}");
        std::wstring head =
            braceRange == std::wstring::npos ? t : t.substr(0, braceRange);
        std::wstring lowHead = Lower(head);

        bool isMenu = lowHead.compare(0, 9, L"menuentry") == 0;
        bool isSub = lowHead.compare(0, 7, L"submenu") == 0;

        if (isSub)
        {
            subStack.push_back(depth);
            suppressed = true;
        }
        else if (isMenu && !suppressed)
        {
            std::wstring title = EntryTitle(t);
            if (!title.empty() && !SkipTitle(title))
            {
                bool dup = false;
                for (size_t j = 0; j < out.size(); j++)
                    if (out[j] == title)
                        dup = true;
                if (!dup)
                    out.push_back(title);
            }
        }

        for (size_t k = 0; k < t.size(); k++)
        {
            if (t[k] == L'{')
                depth++;
            else if (t[k] == L'}')
            {
                depth--;
                if (suppressed && !subStack.empty() &&
                    depth <= subStack.back())
                {
                    subStack.pop_back();
                    suppressed = !subStack.empty();
                }
            }
        }
    }
}

void PrintGrubSystems(const std::vector<std::wstring>& grubCfgs)
{
    if (grubCfgs.empty())
    {
        Out(L"%sgrub detected, but no grub.cfg found in the scan area%s\n",
            col::Dim, col::R);
        return;
    }

    std::vector<std::wstring> systems;
    for (size_t i = 0; i < grubCfgs.size(); i++)
        ParseGrubConfig(grubCfgs[i], systems);

    Out(L"%sgrub.cfg%s at:\n", col::Cyn, col::R);
    for (size_t i = 0; i < grubCfgs.size(); i++)
        Out(L"  %s\n", grubCfgs[i].c_str());

    if (systems.empty())
    {
        Out(L"%sno top-level menu entries parsed (or all advanced/recovery)%s\n",
            col::Dim, col::R);
        return;
    }

    Out(L"%sinstalled systems:%s\n", col::Grn, col::R);
    for (size_t i = 0; i < systems.size(); i++)
        Out(L"  * %s\n", systems[i].c_str());
}

const Sig* Match(const std::wstring& lowerPath)
{
    for (size_t i = 0; i < sizeof(kSigs) / sizeof(kSigs[0]); i++)
    {
        const Sig& s = kSigs[i];
        if (wcschr(s.name, L'\\'))
        {
            if (lowerPath.find(s.name) != std::wstring::npos)
                return &s;
        }
        else
        {
            const wchar_t* base = ExeTail(lowerPath.c_str());
            if (wcscmp(base, s.name) == 0)
                return &s;
        }
    }
    return NULL;
}

wchar_t FreeDrive()
{
    DWORD mask = GetLogicalDrives();
    for (wchar_t c = L'Z'; c >= L'D'; c--)
        if (!(mask & (1u << (c - L'A'))))
            return c;
    return L'Z';
}

} // namespace

void CmdMbr(const std::wstring& path)
{
    bool mounted = false;
    std::wstring scan;

    if (!path.empty())
    {
        DWORD at = GetFileAttributesW(path.c_str());
        if (at == INVALID_FILE_ATTRIBUTES)
        {
            Out(L"%s[!]%s path not found: %s\n", col::Red, col::R,
                path.c_str());
            return;
        }
        scan = path;
        Out(L"%smbr/boot signature scan%s of %s\n", col::Cyn, col::R,
            scan.c_str());
    }
    else
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
        if (ShellExecuteExW(&si) && si.hProcess)
        {
            WaitForSingleObject(si.hProcess, 15000);
            CloseHandle(si.hProcess);
        }

        DWORD at = GetFileAttributesW(mount.c_str());
        if (at == INVALID_FILE_ATTRIBUTES)
        {
            Out(L"%s[!]%s could not access EFI system partition\n", col::Red,
                col::R);
            return;
        }
        mounted = true;
        scan = mount;
        Out(L"%sefi system partition%s mounted at %s\n", col::Cyn, col::R,
            scan.c_str());
    }

    std::vector<std::wstring> files;
    std::vector<std::wstring> grubCfgs;
    Walk(scan, 0, files, grubCfgs);

    if (files.empty())
    {
        Out(L"%sno files found under %s%s\n", col::Dim, scan.c_str(), col::R);
        return;
    }

    std::vector<const Sig*> found;
    for (size_t i = 0; i < files.size(); i++)
    {
        const Sig* s = Match(Lower(files[i]));
        if (s)
            found.push_back(s);
    }

    if (found.empty())
    {
        Out(L"%sno known mbr/boot signatures found%s\n", col::Dim, col::R);
    }
    else
    {
        std::vector<std::wstring> bl, oses;
        for (size_t i = 0; i < found.size(); i++)
        {
            const Sig& s = *found[i];
            bool haveBl = false, haveOs = false;
            for (size_t j = 0; j < bl.size(); j++)
                if (bl[j] == s.bootloader)
                    haveBl = true;
            for (size_t j = 0; j < oses.size(); j++)
                if (oses[j] == s.os)
                    haveOs = true;
            if (!haveBl)
                bl.push_back(s.bootloader);
            if (!haveOs)
                oses.push_back(s.os);
        }
        Out(L"%sdetected:%s", col::Grn, col::R);
        for (size_t j = 0; j < oses.size(); j++)
            Out(L" %s", oses[j].c_str());
        Out(L"\n%sbootloaders:%s", col::Cyn, col::R);
        for (size_t j = 0; j < bl.size(); j++)
            Out(L" %s", bl[j].c_str());
        Out(L"\n\n");

        for (size_t i = 0; i < files.size(); i++)
        {
            const Sig* s = Match(Lower(files[i]));
            if (!s)
                continue;
            unsigned long long sz = 0;
            WIN32_FILE_ATTRIBUTE_DATA a;
            if (GetFileAttributesExW(files[i].c_str(), GetFileExInfoStandard,
                                     &a))
                sz = ((unsigned long long)a.nFileSizeHigh << 32) |
                     a.nFileSizeLow;
            Out(L"%-26s %-22s %-22s %10llu%s\n", s->name, s->bootloader,
                s->os, sz, SizeTag(*s, sz));
        }
    }

    bool grubPresent = false;
    for (size_t i = 0; i < found.size(); i++)
        if (HasGrubSig(found[i]))
            grubPresent = true;
    if (grubPresent || !grubCfgs.empty())
    {
        Out(L"\n");
        PrintGrubSystems(grubCfgs);
    }

    if (mounted)
    {
        SHELLEXECUTEINFOW si2;
        memset(&si2, 0, sizeof(si2));
        si2.cbSize = sizeof(si2);
        si2.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        si2.lpVerb = NULL;
        si2.lpFile = L"C:\\Windows\\System32\\cmd.exe";
        std::wstring un = L"/c mountvol " + scan + L" /D";
        si2.lpParameters = un.c_str();
        si2.nShow = SW_HIDE;
        if (ShellExecuteExW(&si2) && si2.hProcess)
        {
            WaitForSingleObject(si2.hProcess, 10000);
            CloseHandle(si2.hProcess);
        }
    }
}
