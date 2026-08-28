#include "autoruns.h"
#include "sig.h"
#include <shlobj.h>

namespace
{

int g_total = 0;

REGSAM WowAccess(bool wow, bool clean)
{
    REGSAM access = KEY_READ | (clean ? KEY_SET_VALUE : 0);
    if (wow && sizeof(void*) == 8)
        access |= KEY_WOW64_32KEY;
    return access;
}

void VisitValues(HKEY root, const wchar_t* label, const wchar_t* path,
                 bool wow, bool clean, bool reportOnly = false)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, WowAccess(wow, clean && !reportOnly), &k) !=
        ERROR_SUCCESS)
        return;

    DWORD values = 0, maxName = 0, maxValue = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, &values,
                         &maxName, &maxValue, NULL, NULL) != ERROR_SUCCESS ||
        values == 0)
    {
        RegCloseKey(k);
        return;
    }

    Out(L"%s%s\\%s%s\n", col::Cyn, label, path, col::R);
    std::vector<wchar_t> name(maxName + 2, 0);
    std::vector<BYTE> data(maxValue + 2, 0);

    DWORD i = 0;
    for (;;)
    {
        DWORD nl = (DWORD)name.size(), dl = (DWORD)data.size(), ty = 0;
        LONG rc = RegEnumValueW(k, i, name.data(), &nl, NULL, &ty,
                                data.data(), &dl);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS)
            break;
        g_total++;

        std::wstring val;
        if ((ty == REG_SZ || ty == REG_EXPAND_SZ) && dl >= sizeof(wchar_t))
        {
            val.assign((const wchar_t*)data.data(), dl / sizeof(wchar_t));
            size_t z = val.find(L'\0');
            if (z != std::wstring::npos)
                val.resize(z);
            if (ty == REG_EXPAND_SZ)
            {
                wchar_t buf[2048];
                if (ExpandEnvironmentStringsW(val.c_str(), buf, 2048))
                    val = buf;
            }
        }
        else if (ty == REG_BINARY)
            val = L"(binary)";
        else
        {
            wchar_t b[64];
            swprintf(b, 64, L"(type %lu)", (unsigned long)ty);
            val = b;
        }

        Out(L"  %-34s %s\n", name.data(), Trim(val).c_str());

        const wchar_t* tag = SigTagForCommand(val);
        if (tag && wcscmp(tag, L"[signed]") == 0)
            Out(L"%s   %s%s\n", col::Dim, tag, col::R);
        else if (tag)
            Out(L"%s   %s%s\n", col::Yel, tag, col::R);

        if (clean && !reportOnly && AskYN(L"delete?"))
        {
            if (RegDeleteValueW(k, name.data()) == ERROR_SUCCESS)
                Out(L"%s   deleted%s\n", col::Grn, col::R);
            else
                LastErr(L"delete");
            continue;
        }
        i++;
    }
    RegCloseKey(k);
}

void VisitNamed(HKEY root, const wchar_t* label, const wchar_t* path,
                bool wow, const wchar_t* const* names, int nnames,
                const wchar_t* const* defaults, bool clean)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, WowAccess(wow, clean), &k) != ERROR_SUCCESS)
        return;

    for (int i = 0; i < nnames; i++)
    {
        wchar_t buf[2048];
        DWORD sz = sizeof(buf), ty = 0;
        LONG rc = RegQueryValueExW(k, names[i], NULL, &ty, (BYTE*)buf, &sz);
        if (rc != ERROR_SUCCESS)
            continue;

        if (ty == REG_DWORD && sz >= sizeof(DWORD))
        {
            DWORD d = *(const DWORD*)buf;
            g_total++;
            Out(L"%s%s -> %s%s = dword:0x%08lx\n", col::Cyn, label, names[i],
                col::R, (unsigned long)d);
            continue;
        }
        if (!(ty == REG_SZ || ty == REG_EXPAND_SZ))
            continue;

        std::wstring v(buf);
        size_t z = v.find(L'\0');
        if (z != std::wstring::npos)
            v.resize(z);
        if (v.empty())
            continue;
        g_total++;
        Out(L"%s%s -> %s = %s%s\n", col::Cyn, label, names[i], col::R,
            v.c_str());

        if (!clean)
            continue;
        if (defaults[i] && wcscmp(defaults[i], L"@delete") == 0)
        {
            if (AskYN(L"delete value?") &&
                RegDeleteValueW(k, names[i]) == ERROR_SUCCESS)
                Out(L"%s   deleted%s\n", col::Grn, col::R);
        }
        else if (defaults[i] && _wcsicmp(v.c_str(), defaults[i]) != 0 &&
                 AskYN(L"reset to default?"))
        {
            std::wstring def(defaults[i]);
            RegSetValueExW(k, names[i], 0, REG_SZ, (const BYTE*)def.c_str(),
                           (DWORD)((def.size() + 1) * sizeof(wchar_t)));
            Out(L"%s   reset to: %s%s\n", col::Grn, defaults[i], col::R);
        }
    }
    RegCloseKey(k);
}

void VisitSubkeyValue(HKEY root, const wchar_t* label, const wchar_t* path,
                      const wchar_t* valueName, bool wow, bool clean,
                      const wchar_t* askWhat = L"remove?")
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, WowAccess(wow, clean), &k) != ERROR_SUCCESS)
        return;

    DWORD subs = 0, maxSub = 0, maxVal = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, &subs, &maxSub, NULL, NULL,
                         NULL, &maxVal, NULL, NULL) == ERROR_SUCCESS && subs)
    {
        std::vector<wchar_t> sub(maxSub + 2, 0);
        std::vector<BYTE> data(maxVal + 2, 0);
        for (DWORD i = 0; i < subs; i++)
        {
            DWORD nl = (DWORD)sub.size();
            if (RegEnumKeyExW(k, i, sub.data(), &nl, NULL, NULL, NULL,
                              NULL) != ERROR_SUCCESS)
                continue;

            HKEY sk;
            if (RegOpenKeyExW(k, sub.data(), 0,
                              KEY_READ | (clean ? KEY_SET_VALUE : 0),
                              &sk) != ERROR_SUCCESS)
                continue;
            DWORD got = (DWORD)data.size(), ty = 0;
            if (RegQueryValueExW(sk, valueName, NULL, &ty, data.data(),
                                 &got) == ERROR_SUCCESS &&
                (ty == REG_SZ || ty == REG_EXPAND_SZ) && got >= sizeof(wchar_t))
            {
                std::wstring v((const wchar_t*)data.data());
                size_t z = v.find(L'\0');
                if (z != std::wstring::npos)
                    v.resize(z);
                if (!Trim(v).empty())
                {
                    g_total++;
                    Out(L"%s%s\\%s%s\n  %s = %s\n", col::Cyn, label,
                        sub.data(), col::R, valueName, v.c_str());
                    const wchar_t* tag = SigTagForCommand(v);
                    if (tag && wcscmp(tag, L"[signed]") == 0)
                        Out(L"%s   %s%s\n", col::Dim, tag, col::R);
                    else if (tag)
                        Out(L"%s   %s%s\n", col::Yel, tag, col::R);
                    if (clean && AskYN(askWhat))
                        RegDeleteValueW(sk, valueName);
                }
            }
            RegCloseKey(sk);
        }
    }
    RegCloseKey(k);
}

void VisitSubkeys(HKEY root, const wchar_t* label, const wchar_t* path,
                  bool wow, bool clean, bool resolveClsid)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, WowAccess(wow, false), &k) != ERROR_SUCCESS)
        return;

    DWORD subs = 0, maxSub = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, &subs, &maxSub, NULL, NULL, NULL,
                         NULL, NULL, NULL) == ERROR_SUCCESS && subs)
    {
        Out(L"%s%s\\%s%s\n", col::Cyn, label, path, col::R);
        std::vector<wchar_t> sub(maxSub + 2, 0);
        for (DWORD i = 0; i < subs; i++)
        {
            DWORD nl = (DWORD)sub.size();
            if (RegEnumKeyExW(k, i, sub.data(), &nl, NULL, NULL, NULL,
                              NULL) != ERROR_SUCCESS)
                continue;
            g_total++;

            std::wstring extra;
            if (resolveClsid)
            {
                HKEY ck;
                std::wstring clsidPath =
                    std::wstring(L"CLSID\\") + sub.data();
                if (RegOpenKeyExW(HKEY_CLASSES_ROOT, clsidPath.c_str(), 0,
                                  KEY_READ, &ck) == ERROR_SUCCESS)
                {
                    wchar_t nm[512];
                    DWORD nsz = sizeof(nm), ty = 0;
                    if (RegQueryValueExW(ck, NULL, NULL, &ty, (BYTE*)nm,
                                         &nsz) == ERROR_SUCCESS &&
                        (ty == REG_SZ || ty == REG_EXPAND_SZ))
                        extra = nm;
                    RegCloseKey(ck);
                }
            }

            Out(L"  %s%s%s\n", sub.data(),
                extra.empty() ? L"" : L"  ",
                extra.c_str());

            if (clean && AskYN(L"delete key?"))
            {
                if (RegDeleteTreeW(k, sub.data()) == ERROR_SUCCESS)
                    Out(L"%s   deleted%s\n", col::Grn, col::R);
                else
                    LastErr(L"delete");
            }
        }
    }
    RegCloseKey(k);
}

std::vector<std::wstring> SplitMultiSz(const BYTE* data, DWORD cb)
{
    std::vector<std::wstring> out;
    const wchar_t* p = (const wchar_t*)data;
    DWORD n = cb / sizeof(wchar_t);
    DWORD i = 0;
    while (i < n)
    {
        std::wstring s;
        while (i < n && p[i])
            s += p[i++];
        i++;
        if (s.empty() && i >= n)
            break;
        out.push_back(s);
    }
    return out;
}

const wchar_t* const kLsaProtected[] = {
    L"msv1_0",   L"scecli",   L"kerberos", L"pku2u",
    L"spnego",   L"wdigest",  L"livessp",  L"wldp",
};

bool LsaProtected(const std::wstring& s)
{
    for (size_t i = 0; i < _countof(kLsaProtected); i++)
        if (_wcsicmp(s.c_str(), kLsaProtected[i]) == 0)
            return true;
    return false;
}

void VisitLsa(bool clean)
{
    static const wchar_t* vals[] = { L"Authentication Packages",
                                     L"Notification Packages",
                                     L"Security Packages" };
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"System\\CurrentControlSet\\Control\\Lsa", 0,
                      KEY_READ | (clean ? KEY_SET_VALUE : 0),
                      &k) != ERROR_SUCCESS)
        return;

    for (int vi = 0; vi < 3; vi++)
    {
        wchar_t buf[4096];
        DWORD sz = sizeof(buf), ty = 0;
        if (RegQueryValueExW(k, vals[vi], NULL, &ty, (BYTE*)buf, &sz) !=
                ERROR_SUCCESS ||
            ty != REG_MULTI_SZ || sz < sizeof(wchar_t) * 2)
            continue;

        std::vector<std::wstring> items = SplitMultiSz((BYTE*)buf, sz);
        bool changed = false;

        for (size_t ii = 0; ii < items.size(); ii++)
        {
            std::wstring disp = Trim(items[ii]);
            while (!disp.empty() && disp[0] == L'"')
                disp.erase(0, 1);
            while (!disp.empty() && disp[disp.size() - 1] == L'"')
                disp.erase(disp.size() - 1);
            if (disp.empty())
                continue;
            g_total++;
            Out(L"%sHKLM Lsa -> %s = %s%s %s[%s]%s\n", col::Cyn, vals[vi],
                col::R, disp.c_str(), col::Dim,
                LsaProtected(disp) ? L"known" : L"CUSTOM", col::R);

            if (clean && !LsaProtected(disp) &&
                AskYN(L"remove from list?"))
            {
                items.erase(items.begin() + ii);
                ii--;
                changed = true;
            }
        }

        if (changed)
        {
            std::vector<wchar_t> blob;
            for (size_t ii = 0; ii < items.size(); ii++)
            {
                size_t base = blob.size();
                blob.resize(base + items[ii].size() + 1);
                memcpy(blob.data() + base, items[ii].c_str(),
                       (items[ii].size() + 1) * sizeof(wchar_t));
            }
            blob.push_back(0);
            blob.push_back(0);
            if (blob.size() > 2 &&
                RegSetValueExW(k, vals[vi], 0, REG_MULTI_SZ, (const BYTE*)blob.data(),
                               (DWORD)(blob.size() * sizeof(wchar_t))) ==
                    ERROR_SUCCESS)
                Out(L"%s   list rewritten%s\n", col::Grn, col::R);
        }
    }
    RegCloseKey(k);
}

void VisitFolder(const std::wstring& dir, bool clean)
{
    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        if (_wcsicmp(fd.cFileName, L"desktop.ini") == 0)
            continue;
        g_total++;
        Out(L"%sstartup folder:%s\n  %s\\%s\n", col::Cyn, col::R,
            dir.c_str(), fd.cFileName);
        {
            const wchar_t* tag = NULL;
            int vs = VerifyFileSig(dir + L"\\" + fd.cFileName);
            tag = vs == 1 ? L"[signed]" : (vs == 0 ? L"[UNSIGNED]" : NULL);
            if (tag && wcscmp(tag, L"[signed]") == 0)
                Out(L"%s   %s%s\n", col::Dim, tag, col::R);
            else if (tag)
                Out(L"%s   %s%s\n", col::Yel, tag, col::R);
        }
        if (clean && AskYN(L"delete file?"))
        {
            if (DeleteFileW((dir + L"\\" + fd.cFileName).c_str()))
                Out(L"%s   deleted%s\n", col::Grn, col::R);
            else
                LastErr(L"delete");
        }
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
}

void ExtractAscii(const BYTE* utf16, DWORD cb, char* out, DWORD cap)
{
    DWORD a = 0;
    for (DWORD c = 0; c + 1 < cb && a < cap - 1; c += 2)
    {
        unsigned char ch = utf16[c];
        if ((ch >= ' ' && ch < 127) || ch == '\t')
            out[a++] = (char)ch;
    }
    out[a] = 0;
}

void ScanTasks(bool clean)
{
    (void)clean;

    wchar_t tasksDir[MAX_PATH * 2];
    swprintf(tasksDir, MAX_PATH * 2, L"%s\\System32\\Tasks", WinDir().c_str());

    struct Item
    {
        std::wstring rel, full;
    };
    std::vector<Item> stack;
    stack.push_back(Item{ L"", tasksDir });

    while (!stack.empty())
    {
        Item it = stack.back();
        stack.pop_back();

        WIN32_FIND_DATAW fd;
        HANDLE fh = FindFirstFileW((it.full + L"\\*").c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            if (wcscmp(fd.cFileName, L".") == 0 ||
                wcscmp(fd.cFileName, L"..") == 0)
                continue;
            std::wstring rel = it.rel + L"\\" + fd.cFileName;
            std::wstring full = it.full + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                stack.push_back(Item{ rel, full });
                continue;
            }

            HANDLE f = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
            if (f == INVALID_HANDLE_VALUE)
                continue;
            BYTE buf[8192];
            DWORD got = 0;
            ReadFile(f, buf, sizeof(buf), &got, NULL);
            CloseHandle(f);

            char ascii[sizeof(buf) + 1];
            ExtractAscii(buf, got, ascii, sizeof(ascii));

            const char* exe = strstr(ascii, ".exe");
            const char* dll = strstr(ascii, ".dll");
            const char* hit = exe ? exe : dll;
            std::wstring what;
            if (hit)
            {
                const char* s = hit;
                while (s > ascii && s[-1] >= '!' && s[-1] <= '~')
                    s--;
                wchar_t w[512];
                MultiByteToWideChar(CP_ACP, 0, s, -1, w, 512);
                what = w;
            }

            bool ms = rel.find(L"\\Microsoft\\") == 0;
            g_total++;
            Out(L"%stask:%s %s%s%s\n",
                ms ? col::Dim : col::Yel, col::R, rel.c_str(),
                ms ? L"" : L" ", ms ? L"" : L"[3rd-party]");
            if (!what.empty())
            {
                Out(L"  %s", what.c_str());
                const wchar_t* tag = SigTagForCommand(what);
                if (tag && wcscmp(tag, L"[signed]") == 0)
                    Out(L" %s%s%s\n", col::Dim, tag, col::R);
                else if (tag)
                    Out(L" %s%s%s\n", col::Yel, tag, col::R);
                else
                    Out(L"\n");
            }
        } while (FindNextFileW(fh, &fd));
        FindClose(fh);
    }
}

}

void CmdAutoruns(bool clean)
{
    g_total = 0;

    VisitValues(HKEY_CURRENT_USER, L"HKCU",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", false,
                clean);
    VisitValues(HKEY_CURRENT_USER, L"HKCU",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", false,
                clean);
    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", false,
                clean);
    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", false,
                clean);
#ifdef _WIN64
    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM-WOW64",
                L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                true, clean);
#endif

    VisitValues(HKEY_CURRENT_USER, L"HKCU",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
                L"\\Explorer\\Run",
                false, clean);
    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
                L"\\Explorer\\Run",
                false, clean);

    static const wchar_t* nWinlogon[] = { L"Userinit", L"Shell", L"Taskman",
                                          L"AppSetup", L"GinaDLL" };
    static const wchar_t* dWinlogon[] = {
        L"C:\\Windows\\system32\\userinit.exe,", L"explorer.exe",
        L"@delete", L"@delete", L"@delete"
    };
    VisitNamed(HKEY_LOCAL_MACHINE,
               L"HKLM Winlogon",
               L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
               false, nWinlogon, 5, dWinlogon, clean);

    static const wchar_t* nBoot[] = { L"BootExecute" };
    static const wchar_t* dBoot[] = { L"autocheck autochk *" };
    VisitNamed(HKEY_LOCAL_MACHINE,
               L"HKLM Session Manager",
               L"System\\CurrentControlSet\\Control\\Session Manager",
               false, nBoot, 1, dBoot, clean);

    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM AppCertDLLs",
                L"System\\CurrentControlSet\\Control\\Session Manager"
                L"\\AppCertDLLs",
                false, clean);

    static const wchar_t* nCmdAuto[] = { L"AutoRun" };
    static const wchar_t* dCmdAuto[] = { L"@delete" };
    VisitNamed(HKEY_CURRENT_USER, L"HKCU Command Processor",
               L"Software\\Microsoft\\Command Processor", false, nCmdAuto, 1,
               dCmdAuto, clean);
    VisitNamed(HKEY_LOCAL_MACHINE, L"HKLM Command Processor",
               L"Software\\Microsoft\\Command Processor", false, nCmdAuto, 1,
               dCmdAuto, clean);

    static const wchar_t* nAppInit[] = { L"AppInit_DLLs",
                                         L"LoadAppInit_DLLs" };
    static const wchar_t* dAppInit[] = { L"", NULL };
    VisitNamed(HKEY_LOCAL_MACHINE, L"HKLM AppInit",
               L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
               false, nAppInit, 2, dAppInit, clean);
#ifdef _WIN64
    VisitNamed(HKEY_LOCAL_MACHINE, L"HKLM AppInit-WOW64",
               L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
               true, nAppInit, 2, dAppInit, clean);
#endif

    VisitLsa(clean);

    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM SharedTaskScheduler",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                L"\\SharedTaskScheduler",
                false, clean);
#ifdef _WIN64
    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM SharedTaskScheduler-WOW64",
                L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion"
                L"\\Explorer\\SharedTaskScheduler",
                true, clean);
#endif

    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM ShellExecuteHooks",
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                L"\\ShellExecuteHooks",
                false, clean);

    VisitSubkeys(HKEY_LOCAL_MACHINE, L"HKLM ShellServiceObjects",
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                 L"\\ShellServiceObjects",
                 false, clean, false);

    VisitSubkeys(HKEY_LOCAL_MACHINE, L"HKLM IconOverlays",
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                 L"\\ShellIconOverlayIdentifiers",
                 false, clean, false);

    VisitSubkeys(HKEY_LOCAL_MACHINE, L"HKLM BHO",
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                 L"\\Browser Helper Objects",
                 false, false, true);
#ifdef _WIN64
    VisitSubkeys(HKEY_LOCAL_MACHINE, L"HKLM BHO-WOW64",
                 L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion"
                 L"\\Explorer\\Browser Helper Objects",
                 true, false, true);
#endif

    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM TS-Run",
                L"Software\\Microsoft\\Windows NT\\CurrentVersion"
                L"\\Terminal Server\\Install\\Software\\Microsoft\\Windows"
                L"\\CurrentVersion\\Run",
                false, clean);

    VisitValues(HKEY_LOCAL_MACHINE, L"HKLM KnownDLLs",
                L"System\\CurrentControlSet\\Control\\Session Manager"
                L"\\KnownDLLs",
                false, false, true);

    VisitSubkeyValue(
        HKEY_LOCAL_MACHINE, L"HKLM PrintMonitors",
        L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", L"Driver",
        false, clean, L"remove monitor driver?");

    VisitSubkeyValue(
        HKEY_LOCAL_MACHINE, L"HKLM PrintProcessors",
        sizeof(void*) == 8
            ? L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments"
              L"\\Windows x64\\Print Processors"
            : L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments"
              L"\\Windows NT x86\\Print Processors",
        L"Driver", false, clean, L"remove processor driver?");

    static const wchar_t* nNetProv[] = { L"ProviderOrder" };
    VisitNamed(HKEY_LOCAL_MACHINE, L"HKLM NetworkProviders",
               L"System\\CurrentControlSet\\Control\\NetworkProvider\\Order",
               false, nNetProv, 1, nNetProv, false);

    VisitSubkeyValue(
        HKEY_LOCAL_MACHINE, L"HKLM ActiveSetup",
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
        L"StubPath", false, clean);

    PWSTR su = NULL, common = NULL;
    if (SHGetKnownFolderPath(FOLDERID_Startup, 0, NULL, &su) == S_OK)
    {
        VisitFolder(su, clean);
        CoTaskMemFree(su);
    }
    if (SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, NULL, &common) == S_OK)
    {
        VisitFolder(common, clean);
        CoTaskMemFree(common);
    }

    ScanTasks(clean);

    Out(L"%s%d autorun items%s%s\n", col::Cyn, g_total, col::R,
        clean ? L"" : L" (scan only)");
}

const wchar_t* StartTypeName(DWORD t)
{
    switch (t)
    {
    case SERVICE_BOOT_START:   return L"boot";
    case SERVICE_SYSTEM_START: return L"system";
    case SERVICE_AUTO_START:   return L"auto";
    case SERVICE_DEMAND_START: return L"demand";
    case SERVICE_DISABLED:     return L"disabled";
    default:                   return L"?";
    }
}

const wchar_t* StateName(DWORD s)
{
    switch (s)
    {
    case SERVICE_STOPPED:          return L"stopped";
    case SERVICE_START_PENDING:    return L"start_pend";
    case SERVICE_STOP_PENDING:     return L"stop_pend";
    case SERVICE_RUNNING:          return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"cont_pend";
    case SERVICE_PAUSE_PENDING:    return L"pause_pend";
    case SERVICE_PAUSED:           return L"paused";
    default:                       return L"?";
    }
}

void CmdServices()
{
    SC_HANDLE sc = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc)
    {
        LastErr(L"OpenSCManager");
        return;
    }

    std::vector<BYTE> buf(256 * 1024);
    DWORD need = 0, returned = 0, resume = 0;
    BOOL ok = FALSE;
    for (;;)
    {
        resume = 0;
        ok = EnumServicesStatusExW(sc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                   SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(),
                                   &need, &returned, &resume, NULL);
        if (ok)
            break;
        if (GetLastError() != ERROR_MORE_DATA || need == 0)
        {
            LastErr(L"EnumServicesStatusExW");
            CloseServiceHandle(sc);
            return;
        }
        buf.resize(need);
    }

    LPENUM_SERVICE_STATUS_PROCESSW st = (LPENUM_SERVICE_STATUS_PROCESSW)buf.data();
    for (DWORD i = 0; i < returned; i++)
    {
        DWORD start = 0xFFFFFFFF;
        SC_HANDLE sv = OpenServiceW(sc, st[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (sv)
        {
            BYTE cfg[8192];
            DWORD got = 0;
            if (QueryServiceConfigW(sv, (LPQUERY_SERVICE_CONFIGW)cfg, sizeof(cfg), &got))
                start = ((LPQUERY_SERVICE_CONFIGW)cfg)->dwStartType;
            CloseServiceHandle(sv);
        }
        Out(L"%-9s %-10s %-38s %s\n", StartTypeName(start),
            StateName(st[i].ServiceStatusProcess.dwCurrentState),
            st[i].lpServiceName,
            st[i].lpDisplayName ? st[i].lpDisplayName : L"");
    }
    CloseServiceHandle(sc);
    Out(L"%s%lu services%s\n", col::Dim, (unsigned long)returned, col::R);
}

bool DisableService(const std::wstring& name, bool deleteIt)
{
    SC_HANDLE sc = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (!sc)
    {
        LastErr(L"OpenSCManager");
        return false;
    }
    SC_HANDLE sv = OpenServiceW(sc, name.c_str(),
                                deleteIt ? (DELETE | SERVICE_CHANGE_CONFIG)
                                         : SERVICE_CHANGE_CONFIG);
    if (!sv)
    {
        LastErr(L"OpenService");
        CloseServiceHandle(sc);
        return false;
    }
    bool ok = false;
    if (deleteIt)
    {
        ok = DeleteService(sv) != FALSE;
        if (ok)
            Out(L"%s[+]%s '%s' marked for deletion\n", col::Grn, col::R,
                name.c_str());
        else
            LastErr(L"DeleteService");
    }
    else
    {
        ok = ChangeServiceConfigW(sv, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                  SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL) != FALSE;
        if (ok)
            Out(L"%s[+]%s '%s' disabled\n", col::Grn, col::R, name.c_str());
        else
            LastErr(L"ChangeServiceConfig");
    }
    CloseServiceHandle(sv);
    CloseServiceHandle(sc);
    return ok;
}

