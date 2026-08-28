#include "cfg.h"
#include "common.h"

#define CFG_MAGIC 0x49524946u
#define CFG_VER 2

CfgBits g_cfg = { true, true, true, false };

bool SelfReadResource(const wchar_t* resName, std::vector<BYTE>& out)
{
    HRSRC rs = FindResourceW(NULL, resName, (LPCWSTR)RT_RCDATA);
    if (!rs)
        return false;
    HGLOBAL h = LoadResource(NULL, rs);
    if (!h)
        return false;
    DWORD sz = SizeofResource(NULL, rs);
    const void* p = LockResource(h);
    if (!p || !sz)
        return false;
    out.assign((const BYTE*)p, (const BYTE*)p + sz);
    return true;
}

void LoadSelfState()
{
    std::vector<BYTE> blob;
    g_cfg = CfgBits{ true, true, true, false };
    if (!SelfReadResource(L"FIRICFG", blob) ||
        blob.size() < sizeof(DWORD) * 2 + sizeof(CfgBits))
        return;

    DWORD magic = 0, ver = 0;
    memcpy(&magic, blob.data(), 4);
    memcpy(&ver, blob.data() + 4, 4);
    if (magic != CFG_MAGIC || ver != CFG_VER)
        return;

    memcpy(&g_cfg, blob.data() + 8, sizeof(CfgBits));
    if (g_cfg.colors != false && g_cfg.colors != true)
        g_cfg.colors = true;
    if (g_cfg.mouse != false && g_cfg.mouse != true)
        g_cfg.mouse = true;
    if (g_cfg.fontcheck != false && g_cfg.fontcheck != true)
        g_cfg.fontcheck = true;
    if (g_cfg.devmode != false && g_cfg.devmode != true)
        g_cfg.devmode = false;
}

bool SaveCfg()
{
    std::vector<BYTE> blob(sizeof(DWORD) * 2 + sizeof(CfgBits), 0);
    DWORD magic = CFG_MAGIC, ver = CFG_VER;
    memcpy(blob.data(), &magic, 4);
    memcpy(blob.data() + 4, &ver, 4);
    memcpy(blob.data() + 8, &g_cfg, sizeof(CfgBits));
    if (!SelfWriteResource(L"FIRICFG", blob.data(), (DWORD)blob.size()))
    {
        LastErr(L"save settings");
        return false;
    }
    Out(L"%s[+]%s settings saved into firiu.exe\n", col::Grn, col::R);
    return true;
}

/* Self-modifying the running exe: Windows locks the image, so the staged
 * copy ("<self>.new") is produced, the live file is briefly renamed aside
 * ("<self>.prev") to free the name, and the new copy is moved into place.
 * The stale "<self>.prev" is transient -- deleted on reboot
 * (MOVEFILE_DELAY_UNTIL_REBOOT) and cleaned again at next launch by
 * StartupCleanupSelf.  No persistent "firiu.exe.old" is ever left behind. */
static bool SwapSelf()
{
    std::wstring self = SelfPath();
    if (self.empty())
        return false;

    std::wstring tmp = self + L".new";
    std::wstring prev = self + L".prev";

    if (!MoveFileExW(self.c_str(), prev.c_str(), MOVEFILE_REPLACE_EXISTING))
        return false;
    if (!MoveFileExW(tmp.c_str(), self.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        MoveFileExW(prev.c_str(), self.c_str(), MOVEFILE_REPLACE_EXISTING);
        return false;
    }
    MoveFileExW(prev.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    return true;
}

bool SelfWriteResource(const wchar_t* resName, const void* data, DWORD cb)
{
    std::wstring self = SelfPath();
    if (self.empty())
        return false;

    std::wstring tmp = self + L".new";
    DeleteFileW(tmp.c_str());
    if (!CopyFileW(self.c_str(), tmp.c_str(), FALSE))
        return false;

    HANDLE h = BeginUpdateResourceW(tmp.c_str(), FALSE);
    if (!h)
    {
        DeleteFileW(tmp.c_str());
        return false;
    }

    std::vector<BYTE> mut((const BYTE*)data, (const BYTE*)data + cb);
    BOOL uok = UpdateResourceW(h, (LPCWSTR)RT_RCDATA, resName,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               mut.data(), cb);
    BOOL eok = EndUpdateResourceW(h, FALSE);
    if (!uok || !eok)
    {
        DeleteFileW(tmp.c_str());
        return false;
    }

    if (!SwapSelf())
    {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

bool SelfDeleteResource(const wchar_t* resName)
{
    std::wstring self = SelfPath();
    if (self.empty())
        return false;

    std::wstring tmp = self + L".new";
    DeleteFileW(tmp.c_str());
    if (!CopyFileW(self.c_str(), tmp.c_str(), FALSE))
        return false;

    HANDLE h = BeginUpdateResourceW(tmp.c_str(), FALSE);
    if (!h)
    {
        DeleteFileW(tmp.c_str());
        return false;
    }
    BOOL uok = UpdateResourceW(h, (LPCWSTR)RT_RCDATA, resName,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               NULL, 0);
    BOOL eok = EndUpdateResourceW(h, FALSE);
    if (!uok || !eok)
    {
        DeleteFileW(tmp.c_str());
        return false;
    }

    if (!SwapSelf())
    {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

void StartupCleanupSelf()
{
    std::wstring self = SelfPath();
    if (self.empty())
        return;
    DeleteFileW((self + L".old").c_str());
    DeleteFileW((self + L".new").c_str());
    DeleteFileW((self + L".prev").c_str());
}
