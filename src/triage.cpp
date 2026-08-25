#include "triage.h"
#include "autoruns.h"
#include "cfg.h"

#define TRI_MAGIC 0x44495254u

namespace
{

unsigned long long Fnv64(const std::wstring& s)
{
    unsigned long long h = 14695981039346656037ull;
    for (size_t i = 0; i < s.size(); i++)
    {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ull;
        h ^= (unsigned char)(s[i] >> 8);
        h *= 1099511628211ull;
    }
    return h;
}

struct Verd
{
    unsigned long long h;
    BYTE v; // 1 = dangerous, 2 = keep
};

std::vector<Verd> LoadVerdicts()
{
    std::vector<Verd> out;
    std::vector<BYTE> blob;
    if (!SelfReadResource(L"FIRIVERDICTS", blob) || blob.size() < 8)
        return out;
    DWORD magic = 0, count = 0;
    memcpy(&magic, blob.data(), 4);
    memcpy(&count, blob.data() + 4, 4);
    if (magic != TRI_MAGIC)
        return out;
    size_t p = 8;
    for (DWORD i = 0; i < count && p + 9 <= blob.size(); i++)
    {
        Verd e;
        memcpy(&e.h, blob.data() + p, 8);
        e.v = blob[p + 8];
        p += 9;
        if (e.v == 1 || e.v == 2)
            out.push_back(e);
    }
    return out;
}

bool SaveVerdicts(const std::vector<Verd>& vs)
{
    std::vector<BYTE> blob(8, 0);
    DWORD magic = TRI_MAGIC, count = (DWORD)vs.size();
    memcpy(blob.data(), &magic, 4);
    memcpy(blob.data() + 4, &count, 4);
    for (size_t i = 0; i < vs.size(); i++)
    {
        const BYTE* hp = (const BYTE*)&vs[i].h;
        blob.insert(blob.end(), hp, hp + 8);
        blob.insert(blob.end(), vs[i].v);
    }
    return SelfWriteResource(L"FIRIVERDICTS", blob.data(),
                             (DWORD)blob.size());
}

int FindVerd(const std::vector<Verd>& vs, unsigned long long h)
{
    for (size_t i = 0; i < vs.size(); i++)
        if (vs[i].h == h)
            return (int)i;
    return -1;
}

void CaptureScanLines(std::vector<std::wstring>& lines)
{
    std::vector<std::wstring> chunks;
    std::vector<std::wstring>* saved = g_capture;
    g_capture = &chunks;
    CmdAutoruns(false);
    g_capture = saved;

    std::wstring all;
    for (size_t i = 0; i < chunks.size(); i++)
        all += chunks[i];

    size_t s = 0;
    while (s < all.size())
    {
        size_t e = all.find(L'\n', s);
        if (e == std::wstring::npos)
            e = all.size();
        std::wstring line = all.substr(s, e - s);
        while (!line.empty() && line.back() == L'\r')
            line.pop_back();
        lines.push_back(line);
        s = e + 1;
    }
}

std::wstring StripAnsi(const std::wstring& in)
{
    std::wstring out;
    for (size_t i = 0; i < in.size(); i++)
    {
        if (in[i] == 0x1b && i + 1 < in.size())
        {
            size_t j = i + 1;
            if (in[j] == L'[')
            {
                j++;
                while (j < in.size() &&
                       ((in[j] >= L'0' && in[j] <= L'9') ||
                        in[j] == L';' || in[j] == L'?'))
                    j++;
                if (j < in.size())
                    j++;
                i = j - 1;
                continue;
            }
        }
        out += in[i];
    }
    return out;
}

std::wstring TrimW(const std::wstring& s)
{
    size_t a = s.find_first_not_of(L" \t");
    if (a == std::wstring::npos)
        return L"";
    size_t b = s.find_last_not_of(L" \t");
    return s.substr(a, b - a + 1);
}

bool IsFinding(const std::wstring& raw)
{
    if (raw.size() < 4 || raw[0] != L' ')
        return false;
    int sp = 0;
    while (sp < (int)raw.size() && raw[sp] == L' ')
        sp++;
    if (sp != 2)
        return false;
    std::wstring t = TrimW(raw);
    if (t.empty())
        return false;
    return t.find(L":\\") != std::wstring::npos ||
           t.find(L" -> ") != std::wstring::npos;
}

} 

static DWORD MatchTriageKey(const KEY_EVENT_RECORD& ke)
{
    wchar_t ch = ke.uChar.AsciiChar;
    WORD vk = ke.wVirtualKeyCode;
    if (ch == L'y' || ch == L'Y')
        return 2;
    if (ch == L'n' || ch == L'N')
        return 3;
    if (vk == VK_RETURN || vk == VK_SPACE)
        return 4;
    if (vk == VK_ESCAPE)
        return 5;
    return 0;
}

void CmdTriageWizard()
{
    Out(L"scanning autoruns...\n");
    std::vector<std::wstring> lines;
    CaptureScanLines(lines);

    std::vector<Verd> verd = LoadVerdicts();
    bool changed = false;

    std::wstring header;
    int shown = 0;

    for (size_t i = 0; i < lines.size(); i++)
    {
        const std::wstring& raw = lines[i];
        if (!raw.empty() && raw[0] != L' ')
        {
            std::wstring h = TrimW(raw);
            if (!h.empty())
                header = h;
            continue;
        }
        if (!IsFinding(raw))
            continue;

        std::wstring text = StripAnsi(raw);
        unsigned long long h = Fnv64(text);
        int vi = FindVerd(verd, h);
        if (vi >= 0)
            continue;

        shown++;
        Out(L"\n%ssection:%s %s\n", col::Dim, col::R, StripAnsi(header).c_str());
        Out(L"%s%s%s\n", col::Cyn, text.c_str(), col::R);
        Out(L"y=flag dangerous  n=i trust it  enter=skip  esc=stop\n");

        DWORD k = WaitKeys(MatchTriageKey);
        if (k == 5)
            break;
        if (k == 2 || k == 3)
        {
            Verd e;
            e.h = h;
            e.v = (BYTE)(k == 2 ? 1 : 2);
            verd.push_back(e);
            changed = true;
            Out(L"%s->%s %s\n", col::Dim,
                k == 2 ? col::Red : col::Grn,
                k == 2 ? L"DANGEROUS" : L"trusted");
        }
    }

    if (!shown)
    {
        Out(L"%severything already triaged - nothing to review%s\n",
            col::Grn, col::R);
        return;
    }
    if (!changed)
    {
        Out(L"\nno verdicts recorded\n");
        return;
    }
    if (!SaveVerdicts(verd))
    {
        LastErr(L"saving verdicts");
        return;
    }
    int dang = 0;
    for (size_t i = 0; i < verd.size(); i++)
        if (verd[i].v == 1)
            dang++;
    Out(L"\n%s[+]%s saved %d verdict(s) into firiu.exe (%d dangerous)\n",
        col::Grn, col::R, (int)verd.size(), dang);
}

void CmdTriageCheck()
{
    Out(L"scanning autoruns...\n");
    std::vector<std::wstring> lines;
    CaptureScanLines(lines);

    std::vector<Verd> verd = LoadVerdicts();
    if (verd.empty())
    {
        Out(L"%sno triage verdicts stored yet%s (run the wizard)\n", col::Yel,
            col::R);
        return;
    }

    int hits = 0;
    for (size_t i = 0; i < lines.size(); i++)
    {
        const std::wstring& raw = lines[i];
        if (raw.empty() || raw[0] != L' ')
            continue;
        if (!IsFinding(raw))
            continue;
        int vi = FindVerd(verd, Fnv64(StripAnsi(raw)));
        if (vi >= 0 && verd[vi].v == 1)
        {
            Out(L"%s[DANGEROUS]%s %s\n", col::Red, col::R,
                StripAnsi(raw).c_str());
            hits++;
        }
    }

    int trusted = 0;
    for (size_t i = 0; i < verd.size(); i++)
        if (verd[i].v == 2)
            trusted++;

    if (!hits)
        Out(L"%snone of your flagged items are present right now%s\n",
            col::Grn, col::R);
    else
        Out(L"\n%d flagged item(s) ACTIVE on this system\n", hits);
    Out(L"(verdict store: %d dangerous, %d trusted)\n", (int)verd.size() - trusted, trusted);
}

void CmdTriageReset()
{
    if (!SaveVerdicts(std::vector<Verd>()))
    {
        LastErr(L"resetting verdicts");
        return;
    }
    Out(L"%s[+]%s triage verdicts cleared\n", col::Grn, col::R);
}
