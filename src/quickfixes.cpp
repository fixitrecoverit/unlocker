#include "quickfixes.h"
#include "filerestore.h"
#include <shlobj.h>
#include <objbase.h>

namespace
{

const struct
{
    const wchar_t* file;
    const wchar_t* regname;
} kCoreFonts[] = {
    { L"segoeui.ttf", L"Segoe UI (TrueType)" },
    { L"segoeuib.ttf", L"Segoe UI Bold (TrueType)" },
    { L"segoeuii.ttf", L"Segoe UI Italic (TrueType)" },
    { L"segoeuiz.ttf", L"Segoe UI Bold Italic (TrueType)" },
    { L"tahoma.ttf", L"Tahoma (TrueType)" },
    { L"tahomabd.ttf", L"Tahoma Bold (TrueType)" },
    { L"arial.ttf", L"Arial (TrueType)" },
    { L"arialbd.ttf", L"Arial Bold (TrueType)" },
    { L"ariali.ttf", L"Arial Italic (TrueType)" },
    { L"times.ttf", L"Times New Roman (TrueType)" },
    { L"timesbd.ttf", L"Times New Roman Bold (TrueType)" },
    { L"cour.ttf", L"Courier New (TrueType)" },
    { L"courbd.ttf", L"Courier New Bold (TrueType)" },
    { L"calibri.ttf", L"Calibri (TrueType)" },
    { L"calibrib.ttf", L"Calibri Bold (TrueType)" },
    { L"consola.ttf", L"Consolas (TrueType)" },
    { L"symbol.ttf", L"Symbol TrueType" },
    { L"wingding.ttf", L"Wingdings TrueType" },
    { L"marlett.ttf", L"Marlett (TrueType)" },
};

std::wstring FontsDir()
{
    return WinDir() + L"\\Fonts";
}

bool FontFileExists(const std::wstring& name)
{
    return GetFileAttributesW((FontsDir() + L"\\" + name).c_str()) !=
           INVALID_FILE_ATTRIBUTES;
}

bool RegistryFontEntryExists(const std::wstring& filename)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
                      0, KEY_READ, &k) != ERROR_SUCCESS)
        return false;
    bool found = false;
    DWORD values = 0, maxName = 0, maxValue = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, &values,
                         &maxName, &maxValue, NULL, NULL) == ERROR_SUCCESS)
    {
        std::vector<wchar_t> vname(maxName + 2, 0);
        std::vector<BYTE> data(maxValue + 2, 0);
        for (DWORD i = 0; i < values && !found; i++)
        {
            DWORD nl = (DWORD)vname.size(), dl = (DWORD)data.size(), ty = 0;
            if (RegEnumValueW(k, i, vname.data(), &nl, NULL, &ty,
                              data.data(), &dl) != ERROR_SUCCESS)
                break;
            if ((ty == REG_SZ || ty == REG_EXPAND_SZ) && dl >= sizeof(wchar_t))
            {
                std::wstring ref((const wchar_t*)data.data(),
                                 dl / sizeof(wchar_t));
                size_t z = ref.find(L'\0');
                if (z != std::wstring::npos)
                    ref.resize(z);
                if (_wcsicmp(Trim(ref).c_str(), filename.c_str()) == 0)
                    found = true;
            }
        }
    }
    RegCloseKey(k);
    return found;
}

bool RegisterFont(const std::wstring& file, const std::wstring& regname)
{
    HKEY k;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
                            0, KEY_SET_VALUE, &k);
    if (rc != ERROR_SUCCESS)
        return false;
    rc = RegSetValueExW(k, regname.c_str(), 0, REG_SZ,
                        (const BYTE*)file.c_str(),
                        (DWORD)((file.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS)
        return false;

    std::wstring full = FontsDir() + L"\\" + file;
    AddFontResourceW(full.c_str());
    PostMessageW(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);
    return true;
}

void RebuildFontCache()
{
    SC_HANDLE sc = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!sc)
        return;
    SC_HANDLE sv = OpenServiceW(sc, L"FontCache", SERVICE_STOP | SERVICE_START |
                                                     SERVICE_QUERY_STATUS);
    if (sv)
    {
        SERVICE_STATUS st;
        ControlService(sv, SERVICE_CONTROL_STOP, &st);
        Sleep(1500);
        StartServiceW(sv, 0, NULL);
        CloseServiceHandle(sv);
    }
    CloseServiceHandle(sc);

    DeleteFileW((WinDir() + L"\\FNTCACHE.DAT").c_str());
    DeleteFileW((WinDir() + L"\\System32\\FNTCACHE.DAT").c_str());
}

}

static int g_fontRepaired = 0;

int QuickFixFonts(bool interactive)
{
    int repairedFiles = 0, repairedReg = 0, missingNoSource = 0;
    g_fontRepaired = 0;

    std::vector<std::wstring> missingNames;
    for (size_t i = 0; i < sizeof(kCoreFonts) / sizeof(kCoreFonts[0]); i++)
        if (!FontFileExists(kCoreFonts[i].file))
            missingNames.push_back(kCoreFonts[i].file);

    if (!missingNames.empty())
    {
        StoreMap store;
        ScanWinSxS(store, missingNames);

        for (size_t i = 0; i < missingNames.size(); i++)
        {
            StoreMap::iterator it = store.find(LowerCopy(missingNames[i]));
            if (it == store.end() || it->second.empty())
            {
                missingNoSource++;
                continue;
            }
            std::wstring dst = FontsDir() + L"\\" + missingNames[i];
            if (CopyFileW(it->second.front().c_str(), dst.c_str(), FALSE))
            {
                repairedFiles++;
                Out(L"%s[+]%s restored font %s\n", col::Grn, col::R,
                    missingNames[i].c_str());
            }
        }
    }

    for (size_t i = 0; i < sizeof(kCoreFonts) / sizeof(kCoreFonts[0]); i++)
    {
        const wchar_t* file = kCoreFonts[i].file;
        if (!FontFileExists(file))
            continue;
        if (!RegistryFontEntryExists(file))
        {
            std::wstring rn = kCoreFonts[i].regname;
            if (RegisterFont(file, rn))
            {
                repairedReg++;
                Out(L"%s[+]%s re-registered %s\n", col::Grn, col::R, file);
            }
        }
    }

    g_fontRepaired = repairedFiles + repairedReg;

    if (!interactive)
        return g_fontRepaired;

    if (g_fontRepaired || missingNoSource)
    {
        if (AskYN(L"rebuild font cache? (takes a second)"))
        {
            RebuildFontCache();
            Out(L"%s[+]%s cache reset\n", col::Grn, col::R);
        }
    }
    else
        Out(L"%sfonts look fine%s\n", col::Dim, col::R);
    return g_fontRepaired;
}

void CmdForceUac()
{
    if (!IsElevated())
    {
        Out(L"%s[!]%s needs admin - uac is the thing that grants it, chicken and "
             "egg. run as admin.\n",
            col::Red, col::R);
        return;
    }

    HKEY k;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"
                            L"\\System",
                            0, KEY_READ | KEY_SET_VALUE, &k);
    if (rc != ERROR_SUCCESS)
    {
        SetLastError((DWORD)rc);
        LastErr(L"open policies");
        return;
    }

    static const struct
    {
        const wchar_t* name;
        DWORD val;
    } vals[] = {
        { L"EnableLUA", 1 },
        { L"ConsentPromptBehaviorAdmin", 5 },
        { L"ConsentPromptBehaviorUser", 3 },
        { L"PromptOnSecureDesktop", 1 },
        { L"EnableInstallerDetection", 1 },
        { L"EnableVirtualization", 1 },
        { L"EnableSecureUIAPaths", 1 },
        { L"EnableUIADesktopToggle", 0 },
    };

    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++)
    {
        DWORD cur = 0xFFFFFFFF, sz = sizeof(cur), ty = 0;
        BOOL have = RegQueryValueExW(k, vals[i].name, NULL, &ty,
                                     (BYTE*)&cur, &sz) == ERROR_SUCCESS &&
                    ty == REG_DWORD;
        if (have && cur == vals[i].val)
            continue;
        RegSetValueExW(k, vals[i].name, 0, REG_DWORD,
                       (const BYTE*)&vals[i].val, sizeof(DWORD));
        Out(L"%s[+]%s %s = %lu%s\n", col::Grn, col::R, vals[i].name,
            (unsigned long)vals[i].val, col::R);
    }
    RegCloseKey(k);
    Out(L"%s[*]%s reboot needed for uac to fully kick back in\n",
        col::Cyn, col::R);
}

void CmdInstallFiriu()
{
    std::wstring self = SelfPath();

    const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    bool done = false;
    for (int i = 0; i < 2 && !done; i++)
    {
        HKEY k;
        if (RegCreateKeyExW(roots[i],
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App "
                            L"Paths\\firiu.exe",
                            0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                            NULL, &k, NULL) == ERROR_SUCCESS)
        {
            RegSetValueExW(k, NULL, 0, REG_SZ, (const BYTE*)self.c_str(),
                           (DWORD)((self.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(k);
            done = true;
        }
    }
    if (done)
        Out(L"%s[+]%s win+r \"firiu\" works now\n", col::Grn, col::R);
    else
        LastErr(L"app paths");

    std::wstring appsDir;
    PWSTR la = NULL;
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &la) == S_OK)
    {
        appsDir = std::wstring(la) + L"\\Microsoft\\WindowsApps";
        CoTaskMemFree(la);
    }
    std::wstring link;
    if (!appsDir.empty())
        link = appsDir + L"\\firiu.exe";
    if (!link.empty() && CopyFileW(self.c_str(), link.c_str(), FALSE))
        Out(L"%s[+]%s 'firiu' works in cmd now (%s)\n", col::Grn, col::R,
            link.c_str());
    else
        Out(L"%s[!]%s couldn't drop into windowsapps (%s) - add firi's folder "
             "to PATH manually\n",
            col::Yel, col::R, link.empty() ? L"no known folder" : link.c_str());

    if (AskYN(L"also start firiu at logon?"))
    {
        HKEY k;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_SET_VALUE, &k) == ERROR_SUCCESS)
        {
            std::wstring quoted = L"\"" + self + L"\"";
            RegSetValueExW(k, L"firi", 0, REG_SZ,
                           (const BYTE*)quoted.c_str(),
                           (DWORD)((quoted.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(k);
            Out(L"%s[+]%s autorun set\n", col::Grn, col::R);
        }
    }
}
