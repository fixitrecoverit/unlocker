#include "watchdog.h"
#include "cfg.h"
#include <map>

namespace
{

volatile LONG g_stop = 0;

BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT)
    {
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    }
    return FALSE;
}

typedef std::map<std::wstring, std::wstring> IfeoMap;

void CollectView(HKEY root, const wchar_t* path, bool wow,
                 const wchar_t* tag, IfeoMap& out)
{
    REGSAM access = KEY_READ;
    if (wow && sizeof(void*) == 8)
        access |= KEY_WOW64_32KEY;

    HKEY k;
    if (RegOpenKeyExW(root, path, 0, access, &k) != ERROR_SUCCESS)
        return;

    DWORD subs = 0, maxSub = 0;
    if (RegQueryInfoKeyW(k, NULL, NULL, NULL, &subs, &maxSub, NULL, NULL, NULL,
                         NULL, NULL, NULL) == ERROR_SUCCESS && subs)
    {
        std::vector<wchar_t> sub(maxSub + 2, 0);
        for (DWORD i = 0; i < subs; i++)
        {
            DWORD nl = (DWORD)sub.size();
            if (RegEnumKeyExW(k, i, sub.data(), &nl, NULL, NULL, NULL,
                              NULL) != ERROR_SUCCESS)
                continue;

            HKEY sk;
            if (RegOpenKeyExW(k, sub.data(), 0, KEY_READ, &sk) != ERROR_SUCCESS)
                continue;
            wchar_t val[1024];
            DWORD sz = sizeof(val), ty = 0;
            if (RegQueryValueExW(sk, L"Debugger", NULL, &ty, (BYTE*)val,
                                 &sz) == ERROR_SUCCESS &&
                (ty == REG_SZ || ty == REG_EXPAND_SZ))
            {
                std::wstring v(val);
                size_t z = v.find(L'\0');
                if (z != std::wstring::npos)
                    v.resize(z);
                if (!Trim(v).empty())
                    out[std::wstring(tag) + L":" + sub.data()] = v;
            }
            RegCloseKey(sk);
        }
    }
    RegCloseKey(k);
}

IfeoMap Collect()
{
    IfeoMap m;
    const wchar_t* p =
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
        L"Execution Options";
    CollectView(HKEY_LOCAL_MACHINE, p, false, L"64", m);
#ifdef _WIN64
    CollectView(HKEY_LOCAL_MACHINE, p, true, L"32", m);
#endif
    CollectView(HKEY_CURRENT_USER, p, false, L"u", m);
    return m;
}

std::wstring NowStr()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t b[40];
    swprintf(b, 40, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    return b;
}

bool RemoveDebugger(const std::wstring& key)
{
    size_t c = key.find(L':');
    if (c == std::wstring::npos)
        return false;
    std::wstring view = key.substr(0, c);
    std::wstring name = key.substr(c + 1);

    HKEY root = (view == L"u") ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
    REGSAM acc = (view == L"32") ? KEY_SET_VALUE | KEY_WOW64_32KEY
                                 : KEY_SET_VALUE;

    const wchar_t* p =
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
        L"Execution Options";
    HKEY k;
    if (RegOpenKeyExW(root, (std::wstring(p) + L"\\" + name).c_str(), 0, acc,
                      &k) != ERROR_SUCCESS)
        return false;
    LONG ok = RegDeleteValueW(k, L"Debugger");
    RegCloseKey(k);
    return ok == ERROR_SUCCESS;
}

}

void CmdWatchdog(bool autoclean)
{
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    g_stop = 0;

    Out(L"%sifeo watchdog%s live - watching Debugger= hijacks (ctrl+c "
        L"stops)%s\n",
        col::Cyn, col::Yel, col::R);
    Out(L"mode: %s\n", autoclean ? L"AUTO-CLEAN (removes new entries)"
                                 : L"alert only");

    IfeoMap base = Collect();
    Out(L"baseline: %d debugger hook(s)\n\n", (int)base.size());

    int ticks = 0;
    while (!g_stop)
    {
        Sleep(250);
        if (++ticks < 8)
            continue;
        ticks = 0;

        IfeoMap cur = Collect();

        for (IfeoMap::iterator it = cur.begin(); it != cur.end(); ++it)
        {
            IfeoMap::iterator was = base.find(it->first);
            if (was != base.end() && was->second == it->second)
                continue;

            size_t c = it->first.find(L':');
            Out(L"\n%s[%s ALERT]%s new debugger on %s (%s view):\n  %s -> "
                L"%s\n",
                col::Red, NowStr().c_str(), col::R,
                it->first.c_str() + c + 1, it->first.substr(0, c).c_str(),
                it->second.c_str(), col::R);
            MessageBeep(MB_ICONEXCLAMATION);
            MessageBeep(MB_ICONEXCLAMATION);

            if (autoclean)
            {
                if (RemoveDebugger(it->first))
                    Out(L"%s   auto-removed%s\n", col::Grn, col::R);
                else
                    Out(L"%s   remove failed (admin?)%s\n", col::Red, col::R);
            }
        }

        base = cur;
    }
    Out(L"watchdog stopped\n");
}
