#include "snapshots.h"
#include "common.h"
#include "autoruns.h"
#include "cfg.h"
#include <unordered_set>

#define SNAP_MAGIC 0x504E5346u

namespace
{

struct SnapRec
{
    FILETIME ft;
    std::wstring name;
    std::vector<BYTE> data;
};

std::vector<SnapRec> LoadSnaps()
{
    std::vector<SnapRec> out;
    std::vector<BYTE> blob;
    if (!SelfReadResource(L"FIRISNAPS", blob) || blob.size() < 8)
        return out;

    DWORD magic = 0, count = 0;
    memcpy(&magic, blob.data(), 4);
    memcpy(&count, blob.data() + 4, 4);
    if (magic != SNAP_MAGIC)
        return out;

    size_t p = 8;
    for (DWORD i = 0; i < count && p + 10 <= blob.size(); i++)
    {
        SnapRec r;
        memcpy(&r.ft, blob.data() + p, sizeof(FILETIME));
        p += sizeof(FILETIME);

        if (p + 2 > blob.size())
            break;
        unsigned short nl = *(unsigned short*)(blob.data() + p);
        p += 2;

        if (p + nl * sizeof(wchar_t) > blob.size())
            break;
        r.name.assign((const wchar_t*)(blob.data() + p), nl);
        p += nl * sizeof(wchar_t);

        if (p + 4 > blob.size())
            break;
        DWORD dl = *(DWORD*)(blob.data() + p);
        p += 4;

        if (p + dl > blob.size())
            break;
        r.data.assign(blob.data() + p, blob.data() + p + dl);
        p += dl;

        out.push_back(r);
    }
    return out;
}

std::vector<BYTE> PackSnaps(const std::vector<SnapRec>& snaps)
{
    std::vector<BYTE> blob(8, 0);
    DWORD magic = SNAP_MAGIC;
    DWORD count = (DWORD)snaps.size();
    memcpy(blob.data(), &magic, 4);
    memcpy(blob.data() + 4, &count, 4);

    for (size_t i = 0; i < snaps.size(); i++)
    {
        const SnapRec& r = snaps[i];
        const BYTE* ft = (const BYTE*)&r.ft;
        blob.insert(blob.end(), ft, ft + sizeof(FILETIME));

        unsigned short nl = (unsigned short)r.name.size();
        const BYTE* nlp = (const BYTE*)&nl;
        blob.insert(blob.end(), nlp, nlp + 2);
        const BYTE* np = (const BYTE*)r.name.c_str();
        blob.insert(blob.end(), np, np + nl * sizeof(wchar_t));

        DWORD dl = (DWORD)r.data.size();
        const BYTE* dlp = (const BYTE*)&dl;
        blob.insert(blob.end(), dlp, dlp + 4);
        blob.insert(blob.end(), r.data.begin(), r.data.end());
    }
    return blob;
}

bool CaptureScan(std::vector<std::wstring>& lines)
{
    std::vector<std::wstring> chunks;
    std::vector<std::wstring>* saved = g_capture;
    g_capture = &chunks;
    CmdAutoruns(false);
    g_capture = saved;

    std::wstring all;
    for (size_t i = 0; i < chunks.size(); i++)
        all += chunks[i];

    SplitLines(all, lines);
    return !lines.empty();
}

std::wstring FtToStr(const FILETIME& ft)
{
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    wchar_t b[64];
    swprintf(b, 64, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth,
             st.wDay, st.wHour, st.wMinute);
    return b;
}

int FindSnap(const std::vector<SnapRec>& snaps, const std::wstring& name)
{
    for (size_t i = 0; i < snaps.size(); i++)
        if (_wcsicmp(snaps[i].name.c_str(), name.c_str()) == 0)
            return (int)i;
    return -1;
}

}

void CmdSnapSave(const std::wstring& name)
{
    if (name.empty())
    {
        Out(L"[!] usage: snap-save <name>\n");
        return;
    }

    Out(L"scanning autoruns...\n");
    std::vector<std::wstring> lines;
    if (!CaptureScan(lines))
    {
        Out(L"%s[!]%s scan produced nothing\n", col::Red, col::R);
        return;
    }

    SnapRec r;
    GetSystemTimeAsFileTime(&r.ft);
    r.name = name;

    std::wstring all;
    for (size_t i = 0; i < lines.size(); i++)
    {
        all += lines[i];
        all += L"\n";
    }
    int need = WideCharToMultiByte(CP_UTF8, 0, all.c_str(),
                                   (int)all.size(), NULL, 0, NULL, NULL);
    std::string utf8((size_t)(need > 0 ? need : 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, all.c_str(), (int)all.size(), &utf8[0],
                        need, NULL, NULL);
    utf8.resize(need > 0 ? need : 0);
    r.data.assign(utf8.begin(), utf8.end());

    std::vector<SnapRec> snaps = LoadSnaps();
    int ex = FindSnap(snaps, name);
    if (ex >= 0)
    {
        snaps[ex] = r;
        Out(L"(replacing existing '%s')\n", name.c_str());
    }
    else
        snaps.push_back(r);

    std::vector<BYTE> blob = PackSnaps(snaps);
    if (!SelfWriteResource(L"FIRISNAPS", blob.data(), (DWORD)blob.size()))
    {
        LastErr(L"saving snapshot");
        return;
    }
    Out(L"%s[+]%s snapshot '%s' saved (%d lines) into FIRI Unlocker\n",
        col::Grn, col::R, name.c_str(), (int)lines.size());
}

void CmdSnapList()
{
    std::vector<SnapRec> snaps = LoadSnaps();
    if (snaps.empty())
    {
        Out(L"no snapshots yet (snap-save <name>)\n");
        return;
    }
    for (size_t i = 0; i < snaps.size(); i++)
        Out(L"  %-24s %s  %lu kb\n", snaps[i].name.c_str(),
            FtToStr(snaps[i].ft).c_str(),
            (unsigned long)((snaps[i].data.size() + 1023) / 1024));
}

void CmdSnapDiff(const std::wstring& name)
{
    std::vector<SnapRec> snaps = LoadSnaps();
    int idx = FindSnap(snaps, name);
    if (idx < 0)
    {
        Out(L"[!] no snapshot named '%s' (snap-list)\n", name.c_str());
        return;
    }

    Out(L"scanning autoruns now...\n");
    std::vector<std::wstring> now;
    if (!CaptureScan(now))
    {
        Out(L"%s[!]%s scan failed\n", col::Red, col::R);
        return;
    }

    int wneed = MultiByteToWideChar(CP_UTF8, 0, (const char*)snaps[idx].data.data(),
                                    (int)snaps[idx].data.size(), NULL, 0);
    std::vector<wchar_t> wbuf(wneed ? wneed : 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, (const char*)snaps[idx].data.data(),
                        (int)snaps[idx].data.size(), wbuf.data(), wneed);
    std::wstring oldAll(wbuf.data(), wneed);
    std::vector<std::wstring> was;
    SplitLines(oldAll, was);

    std::unordered_multiset<std::wstring> wasBag(was.begin(), was.end());
    int added = 0, removed = 0;

    Out(L"\n%s--- new since '%s' ---%s\n", col::Cyn, name.c_str(), col::R);
    for (size_t i = 0; i < now.size(); i++)
    {
        std::unordered_multiset<std::wstring>::iterator it =
            wasBag.find(now[i]);
        if (it != wasBag.end())
            wasBag.erase(it);
        else
        {
            Out(L"%s+ %s%s\n", col::Grn, now[i].c_str(), col::R);
            added++;
        }
    }

    std::unordered_multiset<std::wstring> nowBag(now.begin(), now.end());
    Out(L"\n%s--- gone since '%s' ---%s\n", col::Cyn, name.c_str(), col::R);
    for (size_t j = 0; j < was.size(); j++)
    {
        std::unordered_multiset<std::wstring>::iterator it =
            nowBag.find(was[j]);
        if (it != nowBag.end())
            nowBag.erase(it);
        else
        {
            Out(L"%s- %s%s\n", col::Red, was[j].c_str(), col::R);
            removed++;
        }
    }

    if (!added && !removed)
        Out(L"%sno changes%s\n", col::Dim, col::R);
    else
        Out(L"\n%d added, %d gone\n", added, removed);
}
