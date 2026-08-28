#include "repairs.h"

namespace
{

std::wstring HostsPath()
{
    return SysDir() + L"\\drivers\\etc\\hosts";
}

}

void CmdFixHosts()
{
    std::wstring hosts = HostsPath();
    std::wstring bak = hosts + L".firi-bak";

    DWORD attrs = GetFileAttributesW(hosts.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES)
    {
        if (!CopyFileW(hosts.c_str(), bak.c_str(), FALSE))
        {
            LastErr(L"CopyFileW (backup)");
            return;
        }
        Out(L"[*] original hosts backed up to %s\n", bak.c_str());
    }

    static const char def[] =
        "# restored by fixitrecoverit (FIRI Project)\r\n"
        "127.0.0.1\tlocalhost\r\n"
        "::1\tlocalhost\r\n";

    HANDLE f = CreateFileW(hosts.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        LastErr(L"CreateFileW (hosts)");
        return;
    }
    DWORD written = 0;
    WriteFile(f, def, (DWORD)(sizeof(def) - 1), &written, NULL);
    CloseHandle(f);
    Out(L"[+] hosts file reset (%lu bytes written)\n", (unsigned long)written);
}

void CmdFixProxy()
{
    HKEY k;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                            0, KEY_READ | KEY_SET_VALUE, &k);
    if (rc != ERROR_SUCCESS)
    {
        SetLastError((DWORD)rc);
        LastErr(L"RegOpenKeyExW (Internet Settings)");
        return;
    }

    DWORD en = 0, sz = sizeof(en), ty = 0;
    if (RegQueryValueExW(k, L"ProxyEnable", NULL, &ty, (BYTE*)&en, &sz) == ERROR_SUCCESS &&
        ty == REG_DWORD && en)
        Out(L"[*] WinINET proxy was ENABLED\n");
    else
        Out(L"[*] WinINET proxy already disabled\n");

    DWORD zero = 0;
    if (RegSetValueExW(k, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero)) ==
        ERROR_SUCCESS)
        Out(L"[+] ProxyEnable -> 0\n");

    const wchar_t* names[] = { L"ProxyServer", L"AutoConfigURL" };
    for (int i = 0; i < 2; i++)
    {
        rc = RegDeleteValueW(k, names[i]);
        if (rc == ERROR_SUCCESS)
            Out(L"[+] deleted value '%s'\n", names[i]);
    }
    RegCloseKey(k);
    Out(L"[i] note: some malware sets WinHTTP proxy too ('netsh winhttp reset proxy')\n");
}

void CmdIfeo(bool clean);

namespace
{

const wchar_t* const kPolicyPaths[] = {
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
};

const wchar_t* const kRestrictNames[] = {
    L"DisableTaskMgr", L"DisableCMD", L"DisableRegistryTools",
    L"NoRun", L"NoControlPanel", L"NoViewOnDrive", L"NoDrives",
    L"NoSetTaskbar", L"NoClose", L"NoLogoff", L"NoDesktop",
    L"NoFind", L"NoFileMenu", L"NoTrayContextMenu", L"NoWinKeys",
    L"DisableChangePassword", L"DisableLockWorkstation",
    L"HideFastUserSwitching",
};

bool IsRestrictName(const std::wstring& n)
{
    std::wstring ln = Lower(n);
    for (size_t i = 0; i < _countof(kRestrictNames); i++)
        if (ln == Lower(kRestrictNames[i]))
            return true;
    return false;
}

void SweepPolicyKey(HKEY root, const wchar_t* path, bool fix)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0,
                      KEY_READ | (fix ? KEY_SET_VALUE : 0),
                      &k) != ERROR_SUCCESS)
        return;

    DWORD values = 0, maxName = 0, maxValue = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, &values,
                         &maxName, &maxValue, NULL, NULL) == ERROR_SUCCESS &&
        values)
    {
        std::vector<wchar_t> name(maxName + 2, 0);
        std::vector<BYTE> data(maxValue + 2, 0);
        DWORD i = 0;
        while (i < values)
        {
            DWORD nl = (DWORD)name.size(), dl = (DWORD)data.size(), ty = 0;
            if (RegEnumValueW(k, i, name.data(), &nl, NULL, &ty, data.data(),
                              &dl) != ERROR_SUCCESS)
                break;
            i++;

            bool hit = false;
            if (!IsRestrictName(name.data()))
                continue;
            if (ty == REG_DWORD && dl >= sizeof(DWORD))
                hit = *(const DWORD*)data.data() != 0;
            else if ((ty == REG_SZ || ty == REG_EXPAND_SZ) &&
                     dl >= sizeof(wchar_t) * 2)
                hit = !Trim(std::wstring((const wchar_t*)data.data())).empty();

            if (!hit)
                continue;

            Out(L"%srestriction:%s %s -> %s\n", col::Yel, col::R, path,
                name.data());
            if (fix && AskYN(L"remove restriction?"))
            {
                if (RegDeleteValueW(k, name.data()) == ERROR_SUCCESS)
                    Out(L"%s   removed%s\n", col::Grn, col::R);
                else
                    LastErr(L"delete");
                i--;
            }
        }
    }
    RegCloseKey(k);
}

void SweepDisallowRun(HKEY root, bool fix)
{
    std::wstring path =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
        L"\\Explorer\\DisallowRun";
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS)
        return;

    DWORD values = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, &values, NULL,
                         NULL, NULL, NULL) == ERROR_SUCCESS &&
        values > 0)
    {
        Out(L"%sDisallowRun list:%s %s (%lu apps blocked)\n", col::Yel,
            col::R, path.c_str(), (unsigned long)values);
        RegCloseKey(k);
        if (fix && AskYN(L"delete whole DisallowRun key?"))
        {
            HKEY pk;
            if (RegOpenKeyExW(
                    root,
                    L"Software\\Microsoft\\Windows\\CurrentVersion"
                    L"\\Policies\\Explorer",
                    0, KEY_SET_VALUE | DELETE | KEY_ENUMERATE_SUB_KEYS,
                    &pk) == ERROR_SUCCESS)
            {
                if (RegDeleteTreeW(pk, L"DisallowRun") == ERROR_SUCCESS)
                    Out(L"%s   deleted%s\n", col::Grn, col::R);
                else
                    LastErr(L"delete tree");
                RegCloseKey(pk);
            }
            return;
        }
        return;
    }
    RegCloseKey(k);
}

}

void CmdUnrestrict(bool fix)
{
    Out(L"%srestriction sweep%s (%s mode)\n", col::Cyn, col::R,
        fix ? L"clean" : L"scan");

    static const wchar_t* ifeo =
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
        L"Execution Options";
    int passes = sizeof(void*) == 8 ? 2 : 1;
    for (int pass = 0; pass < passes; pass++)
    {
        REGSAM acc = KEY_READ | (fix ? KEY_SET_VALUE : 0) |
                     (pass == 1 ? KEY_WOW64_32KEY : 0);
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeo, 0, acc, &k) !=
            ERROR_SUCCESS)
            continue;
        DWORD subs = 0, maxSub = 0;
        if (RegQueryInfoKeyW(k, NULL, NULL, NULL, &subs, &maxSub, NULL, NULL,
                             NULL, NULL, NULL, NULL) == ERROR_SUCCESS && subs)
        {
            std::vector<wchar_t> sub(maxSub + 2, 0);
            for (DWORD i = 0; i < subs; i++)
            {
                DWORD nl = (DWORD)sub.size();
                if (RegEnumKeyExW(k, i, sub.data(), &nl, NULL, NULL, NULL,
                                  NULL) != ERROR_SUCCESS)
                    continue;
                HKEY sk;
                if (RegOpenKeyExW(k, sub.data(), 0,
                                  KEY_QUERY_VALUE |
                                      (fix ? KEY_SET_VALUE : 0),
                                  &sk) != ERROR_SUCCESS)
                    continue;
                wchar_t val[1024];
                DWORD sz = sizeof(val), ty = 0;
                if (RegQueryValueExW(sk, L"Debugger", NULL, &ty, (BYTE*)val,
                                     &sz) == ERROR_SUCCESS &&
                    (ty == REG_SZ || ty == REG_EXPAND_SZ))
                {
                    std::wstring dbg(val);
                    size_t z = dbg.find(L'\0');
                    if (z != std::wstring::npos)
                        dbg.resize(z);
                    Out(L"%sifeo debugger:%s %s%s%s -> %s\n", col::Yel,
                        col::R, col::Cyn, sub.data(), col::R, dbg.c_str());
                    if (fix && AskYN(L"remove debugger hijack?"))
                    {
                        if (RegDeleteValueW(sk, L"Debugger") ==
                            ERROR_SUCCESS)
                            Out(L"%s   removed%s\n", col::Grn, col::R);
                        else
                            LastErr(L"delete");
                    }
                }
                RegCloseKey(sk);
            }
        }
        RegCloseKey(k);
    }

    for (int r = 0; r < 2; r++)
    {
        HKEY root = r == 0 ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
        for (size_t i = 0; i < _countof(kPolicyPaths); i++)
            SweepPolicyKey(root, kPolicyPaths[i], fix);
        SweepDisallowRun(root, fix);
    }

    Out(L"%sdone%s\n", col::Dim, col::R);
}
