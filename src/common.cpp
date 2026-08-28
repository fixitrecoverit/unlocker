#include "common.h"

const wchar_t* kVersion = L"0.2.1";

static bool g_vt = false;
bool g_colorsOff = false;
std::vector<std::wstring>* g_capture = NULL;

static void CookedStdin(bool on, DWORD* saved);

namespace col
{
const wchar_t *R = L"", *Dim = L"", *Red = L"", *Grn = L"", *Yel = L"",
              *Cyn = L"", *Wht = L"", *Inv = L"", *HideCur = L"",
              *ShowCur = L"", *Sel = L"";
const wchar_t *RedB = L"", *Link = L"";
}

int BootMode()
{
    static int mode = -1;
    if (mode >= 0)
        return mode;

    int kind = 0;
    if (IsSafeMode(&kind))
    {
        mode = 1;
        return mode;
    }

    HKEY k = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\MiniNT", 0,
                      KEY_READ, &k) == ERROR_SUCCESS)
    {
        RegCloseKey(k);
        mode = 2;
        return mode;
    }

    wchar_t windir[MAX_PATH] = L"";
    GetWindowsDirectoryW(windir, MAX_PATH);
    mode = (windir[0] && towupper(windir[0]) == L'X') ? 2 : 0;
    return mode;
}

static void StripEsc(wchar_t* s, DWORD& cch)
{
    DWORD w = 0;
    for (DWORD i = 0; i < cch; i++)
    {
        if (s[i] == 0x1b && i + 1 < cch && s[i + 1] == L'[')
        {
            i += 2;
            while (i < cch && !(s[i] >= 0x40 && s[i] <= 0x7e))
                i++;
            continue;
        }
        s[w++] = s[i];
    }
    cch = w;
}

static void WriteRaw(const wchar_t* s, DWORD cch)
{
    if (!s || !cch)
        return;    wchar_t local[16384];
    const wchar_t* out = s;
    if (g_colorsOff)
    {
        if (cch > 16383)
            cch = 16383;
        memcpy(local, s, cch * sizeof(wchar_t));
        StripEsc(local, cch);
        local[cch] = 0;
        out = local;
    }
    if (g_capture)
    {
        g_capture->push_back(std::wstring(out, cch));
    }
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
    {
        DWORD written = 0;
        WriteConsoleW(h, out, cch, &written, NULL);
        return;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, out, (int)cch, NULL, 0, NULL, NULL);
    if (n > 0)
    {
        std::string utf8((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, out, (int)cch, &utf8[0], n, NULL, NULL);
        DWORD written = 0;
        WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, NULL);
    }
}

void Out(const wchar_t* fmt, ...)
{
    wchar_t buf[16384];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnwprintf(buf, 16383, fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 16383;
    buf[n] = L'\0';
    WriteRaw(buf, (DWORD)n);
}

void LastErr(const wchar_t* what)
{
    DWORD e = GetLastError();
    wchar_t msg[1024];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, e, 0, msg, 1024, NULL);
    std::wstring t(msg, n ? n : 0);
    while (!t.empty() && (t.back() == L'\r' || t.back() == L'\n' || t.back() == L' '))
        t.pop_back();
    Out(L"%s[!]%s %s failed (%lu): %s\n", col::Red, col::R, what,
        (unsigned long)e, t.empty() ? L"unknown error" : t.c_str());
}

void InitConsole()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut && hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode))
    {
        if (SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                                      ENABLE_PROCESSED_OUTPUT))
            g_vt = true;
    }

    if (g_vt)
    {
        col::R = L"\x1b[0m";
        col::Dim = L"\x1b[90m";
        col::Red = L"\x1b[91m";
        col::Grn = L"\x1b[92m";
        col::Yel = L"\x1b[93m";
        col::Cyn = L"\x1b[96m";
        col::Wht = L"\x1b[97m";
        col::Inv = L"\x1b[7m";
        int bm = BootMode();
        col::Sel = bm == 1 ? L"\x1b[97;44m"
                           : (bm == 2 ? L"\x1b[97;41m" : L"\x1b[97;42m");
        col::HideCur = L"\x1b[?25l";
        col::ShowCur = L"\x1b[?25h";
        col::RedB = L"\x1b[1;91m";
        col::Link = L"\x1b[4;96m";
    }

    SetConsoleTitleW(L"FIRI Unlocker v0.2.1");

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn && hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &mode))
        SetConsoleMode(hIn, mode | ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT |
                                ENABLE_EXTENDED_FLAGS);
}

bool StdoutIsConsole()
{
    DWORD mode = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    return h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) != 0;
}

bool StdinIsConsole()
{
    DWORD mode = 0;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    return h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) != 0;
}

void ClrScr()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (!h || h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode))
        return;

    CONSOLE_SCREEN_BUFFER_INFO bi;
    if (!GetConsoleScreenBufferInfo(h, &bi))
        return;

    DWORD cells = (DWORD)bi.dwSize.X * (DWORD)bi.dwSize.Y;
    COORD origin = {0, 0};
    DWORD wrote = 0;
    FillConsoleOutputCharacterW(h, L' ', cells, origin, &wrote);
    FillConsoleOutputAttribute(h, bi.wAttributes, cells, origin, &wrote);
    SetConsoleCursorPosition(h, origin);
}

bool WaitKeys(DWORD (*match)(const KEY_EVENT_RECORD& ke))
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (!h || h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode))
    {
        wchar_t b[64];
        return fgetws(b, 64, stdin) != NULL;
    }
    FlushConsoleInputBuffer(h);

    for (;;)
    {
        INPUT_RECORD rec[16];
        DWORD n = 0;
        if (!ReadConsoleInputW(h, rec, 16, &n) || n == 0)
            return false;
        for (DWORD i = 0; i < n; i++)
        {
            if (rec[i].EventType != KEY_EVENT)
                continue;
            const KEY_EVENT_RECORD& k = rec[i].Event.KeyEvent;
            if (!k.bKeyDown)
                continue;
            DWORD r = match(k);
            if (r == 2)
                return true;
            if (r == 1)
                return false;
        }
    }
}

static DWORD MatchEnter(const KEY_EVENT_RECORD& ke)
{
    WORD vk = ke.wVirtualKeyCode;
    if (vk == VK_RETURN || vk == VK_ESCAPE || vk == VK_SPACE)
        return 2;
    return 0;
}

static DWORD MatchYN(const KEY_EVENT_RECORD& ke)
{
    wchar_t ch = ke.uChar.AsciiChar;
    WORD vk = ke.wVirtualKeyCode;
    if (ch == L'y' || ch == L'Y')
        return 2;
    if (ch == L'n' || ch == L'N')
        return 1;
    if (vk == VK_RETURN || vk == VK_ESCAPE)
        return 1;
    return 0;
}

static DWORD MatchYNYes(const KEY_EVENT_RECORD& ke)
{
    wchar_t ch = ke.uChar.AsciiChar;
    WORD vk = ke.wVirtualKeyCode;
    if (ch == L'n' || ch == L'N')
        return 1;
    if (vk == VK_ESCAPE)
        return 1;
    if (ch == L'y' || ch == L'Y')
        return 2;
    if (vk == VK_RETURN || vk == VK_SPACE)
        return 2;
    return 0;
}

void PauseEnter()
{
    Out(L"%s[enter] back%s\n", col::Dim, col::R);
    WaitKeys(MatchEnter);
}

void OpenUrl(const std::wstring& url)
{
    HINSTANCE r = ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL,
                                SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32)
        Out(L"%s[!]%s could not open %s\n", col::Red, col::R, url.c_str());
}

bool IsElevated()
{
    BOOL isAdmin = FALSE;
    PSID group = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group))
    {
        CheckTokenMembership(NULL, group, &isAdmin);
        FreeSid(group);
    }
    return isAdmin != FALSE;
}

bool EnableDebugPriv()
{
    return EnablePrivByName(SE_DEBUG_NAME);
}

bool EnablePrivByName(const wchar_t* name)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    TOKEN_PRIVILEGES tp;
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL found = LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid);
    bool ok = false;
    if (found)
    {
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
        ok = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    }
    CloseHandle(tok);
    return ok;
}

bool IsSafeMode(int* kind)
{
    int v = GetSystemMetrics(SM_CLEANBOOT);
    if (kind)
        *kind = v;
    return v != 0;
}

std::wstring SysDir()
{
    wchar_t b[MAX_PATH];
    UINT n = GetSystemDirectoryW(b, MAX_PATH);
    return std::wstring(b, n);
}

std::wstring WinDir()
{
    wchar_t b[MAX_PATH];
    UINT n = GetWindowsDirectoryW(b, MAX_PATH);
    return std::wstring(b, n);
}

std::wstring Lower(const std::wstring& s)
{
    std::wstring r = s;
    for (size_t i = 0; i < r.size(); i++)
        r[i] = (wchar_t)towlower(r[i]);
    return r;
}

std::wstring Trim(const std::wstring& s)
{
    size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a]))
        a++;
    while (b > a && iswspace(s[b - 1]))
        b--;
    return s.substr(a, b - a);
}

std::wstring Trim(const wchar_t* s)
{
    return s ? Trim(std::wstring(s)) : std::wstring();
}

bool IsAllDigits(const std::wstring& s)
{
    if (s.empty())
        return false;
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] < L'0' || s[i] > L'9')
            return false;
    return true;
}

void SplitLines(const std::wstring& text, std::vector<std::wstring>& lines)
{
    lines.clear();
    size_t s = 0;
    while (s < text.size())
    {
        size_t e = text.find(L'\n', s);
        if (e == std::wstring::npos)
            e = text.size();
        std::wstring line = text.substr(s, e - s);
        while (!line.empty() && line.back() == L'\r')
            line.pop_back();
        lines.push_back(line);
        s = e + 1;
    }
}

static void CookedStdin(bool on, DWORD* saved)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE)
        return;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode))
        return;
    if (on)
    {
        *saved = mode;
        SetConsoleMode(h, (mode | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
                           ENABLE_PROCESSED_INPUT) &
                              ~ENABLE_MOUSE_INPUT);
    }
    else
        SetConsoleMode(h, *saved);
}

void FlushStdin()
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        FlushConsoleInputBuffer(h);
}

std::wstring PromptLine(const wchar_t* label)
{
    Out(L"%s", label);
    Out(L"%s", col::ShowCur);
    wchar_t buf[2048];
    DWORD saved = 0;
    CookedStdin(true, &saved);
    wchar_t* r = fgetws(buf, 2048, stdin);
    CookedStdin(false, &saved);
    fflush(stdin);
    if (!r)
        return std::wstring();
    return Trim(buf);
}

bool AskYN(const wchar_t* question)
{
    Out(L"%s   %s [y/N]%s ", col::Dim, question, col::R);
    Out(L"%s", col::ShowCur);
    bool yes = WaitKeys(MatchYN);
    Out(L"%s\n", yes ? L"y" : L"n");
    return yes;
}

bool AskYNDef(const wchar_t* question)
{
    Out(L"%s%s [Y/n]%s ", col::Dim, question, col::R);
    Out(L"%s", col::ShowCur);
    bool yes = WaitKeys(MatchYNYes);
    Out(L"%s\n", yes ? L"y" : L"n");
    return yes;
}

std::wstring SelfPath()
{
    wchar_t b[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(NULL, b, MAX_PATH * 2);
    return std::wstring(b, n);
}
