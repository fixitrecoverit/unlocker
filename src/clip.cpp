#include "clip.h"
#include <string>

namespace
{

volatile long g_stopClip = 0;

BOOL WINAPI ClipCtrl(DWORD t)
{
    if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT ||
        t == CTRL_CLOSE_EVENT)
    {
        InterlockedExchange(&g_stopClip, 1);
        return TRUE;
    }
    return FALSE;
}

std::wstring Sanitize(const wchar_t* s, size_t maxch)
{
    std::wstring out;
    for (size_t i = 0; s[i] && out.size() < maxch; i++)
    {
        wchar_t c = s[i];
        if (c == L'\r' || c == L'\n')
            c = L' ';
        else if (c < L' ')
            continue;
        out += c;
    }
    return out;
}

}

void CmdClipSentry()
{
    SetConsoleCtrlHandler(ClipCtrl, TRUE);
    Out(L"%sclipboard sentry%s running - ctrl+c to stop\n", col::Cyn, col::R);
    Out(L"beeps on every clipboard change and shows a preview\n\n");

    DWORD last = GetClipboardSequenceNumber();

    while (!g_stopClip)
    {
        Sleep(300);
        DWORD now = GetClipboardSequenceNumber();
        if (now == last || now == 0)
            continue;
        last = now;

        bool shown = false;
        for (int attempt = 0; attempt < 5 && !shown; attempt++)
        {
            if (!OpenClipboard(NULL))
            {
                Sleep(120);
                continue;
            }
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            if (h)
            {
                const wchar_t* txt = (const wchar_t*)GlobalLock(h);
                if (txt)
                {
                    SYSTEMTIME st;
                    GetLocalTime(&st);
                    Out(L"%s%02u:%02u:%02u%s clipboard: %s\"%s\"%s\n",
                        col::Dim, st.wHour, st.wMinute, st.wSecond, col::R,
                        col::Yel, Sanitize(txt, 80).c_str(), col::R);
                    GlobalUnlock(h);
                    shown = true;
                }
            }
            else
            {
                UINT fmt = 0;
                fmt = EnumClipboardFormats(fmt);
                SYSTEMTIME st;
                GetLocalTime(&st);
                Out(L"%s%02u:%02u:%02u%s clipboard changed (%s)\n", col::Dim,
                    st.wHour, st.wMinute, st.wSecond, col::R,
                    fmt ? L"non-text data" : L"empty");
                shown = true;
            }
            CloseClipboard();
        }

        MessageBeep(MB_OK);
        Sleep(150);
        MessageBeep(MB_OK);
    }

    SetConsoleCtrlHandler(ClipCtrl, FALSE);
    Out(L"\nstopped.\n");
}
