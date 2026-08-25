#include "ads.h"

namespace
{

struct Hit
{
    std::wstring file;
    std::wstring stream;
    unsigned long long size;
    bool zone;
};

bool IsHotspotBase(const std::wstring& dir, std::vector<std::wstring>& out)
{
    DWORD at = GetFileAttributesW(dir.c_str());
    if (at == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY))
        return false;
    out.push_back(dir);
    return true;
}

void ScanFile(const std::wstring& path, std::vector<Hit>& out)
{
    WIN32_FIND_STREAM_DATA fsd;
    HANDLE s = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (s == INVALID_HANDLE_VALUE)
        return;
    do
    {
        std::wstring sn(fsd.cStreamName);
        if (_wcsicmp(sn.c_str(), L"::$DATA") == 0)
            continue;

        Hit h;
        h.file = path;
        h.stream = sn;
        h.size = fsd.StreamSize.QuadPart;
        std::wstring low = Lower(sn);
        h.zone = low.find(L"zone.identifier") != std::wstring::npos;
        if (!h.zone || h.size > 0)
            out.push_back(h);
    } while (FindNextStreamW(s, &fsd));
    FindClose(s);
}

void Walk(const std::wstring& dir, int depth, std::vector<Hit>& out,
          int& scanned)
{
    if (depth > 6 || scanned > 60000)
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

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            Walk(full, depth + 1, out, scanned);
            continue;
        }

        scanned++;
        ScanFile(full, out);

        if ((scanned % 5000) == 0)
            Out(L"%s...%d files%s\n", col::Dim, scanned, col::R);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
}

void Report(const std::vector<Hit>& hits)
{
    int suspicious = 0;
    for (size_t i = 0; i < hits.size(); i++)
    {
        const Hit& h = hits[i];
        if (h.zone && h.size == 0)
            continue;
        bool exeish = Lower(h.stream).find(L".exe") != std::wstring::npos ||
                      Lower(h.stream).find(L".dll") != std::wstring::npos;
        Out(L"%s%s%s\n  stream %s (%llu bytes)%s\n",
            exeish ? col::Red : (h.zone ? L"" : col::Yel), h.file.c_str(),
            exeish ? L"" : col::R, h.stream.c_str(), h.size,
            h.zone ? L"" : L"");
        if (h.zone)
            Out(L"%s   [zone marker]%s\n", col::Dim, col::R);
        if (!h.zone)
            suspicious++;
    }
    if (hits.empty())
        Out(L"%sno alternate streams found%s\n", col::Dim, col::R);
    else
        Out(L"\n%d stream(s) (%d non-zone)\n", (int)hits.size(), suspicious);
}

} 

void CmdAds(const std::wstring& pathIn)
{
    std::vector<Hit> hits;
    int scanned = 0;

    if (!pathIn.empty())
    {
        wchar_t abs[1024];
        GetFullPathNameW(pathIn.c_str(), 1024, abs, NULL);
        DWORD at = GetFileAttributesW(abs);
        if (at == INVALID_FILE_ATTRIBUTES)
        {
            Out(L"[!] not found: %s\n", abs);
            return;
        }
        Out(L"%sscanning ads:%s %s\n", col::Cyn, col::R, abs);
        if (at & FILE_ATTRIBUTE_DIRECTORY)
            Walk(abs, 0, hits, scanned);
        else
        {
            scanned = 1;
            ScanFile(abs, hits);
        }
    }
    else
    {
        std::vector<std::wstring> bases;
        const wchar_t* profile = _wgetenv(L"USERPROFILE");
        const wchar_t* local = _wgetenv(L"LOCALAPPDATA");
        if (profile)
        {
            IsHotspotBase(std::wstring(profile) + L"\\Downloads", bases);
            IsHotspotBase(std::wstring(profile) + L"\\Desktop", bases);
            IsHotspotBase(std::wstring(profile) +
                              L"\\AppData\\Roaming\\Microsoft\\Windows"
                              L"\\Start Menu\\Programs\\Startup",
                          bases);
        }
        if (local)
            IsHotspotBase(std::wstring(local) + L"\\Temp", bases);
        IsHotspotBase(WinDir() + L"\\Temp", bases);

        Out(L"%sscanning hotspots for ads...%s\n", col::Cyn, col::R);
        for (size_t i = 0; i < bases.size(); i++)
            Walk(bases[i], 0, hits, scanned);
    }

    Out(L"%s%d files scanned%s\n", col::Dim, scanned, col::R);
    Report(hits);
}
