#include "ui.h"
#include "cfg.h"

static COORD g_itemOrigin = {0, 0};
static int g_rows = 0;
static bool g_twoCol = false;
static int g_midX = 0;

struct MenuState
{
    const wchar_t* title;
    const MenuItem* items;
    int count;
    int sel;
};

static void DrawItem(MenuState& st, int idx, bool hover)
{
    Out(L" %s%s%s %s[%c]%s %-22s",
        hover ? col::Sel : L"",
        hover ? L">" : L" ",
        hover ? col::R : L"",
        col::Wht,
        (wchar_t)st.items[idx].key,
        col::R,
        st.items[idx].label);
}

static void DrawAll(MenuState& st)
{
    ClrScr();
    Out(L"\n %s%s v%s%s\n\n", col::Wht, st.title, kVersion, col::R);
    CONSOLE_SCREEN_BUFFER_INFO bi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(h, &bi))
        g_itemOrigin = bi.dwCursorPosition;

    g_twoCol = st.count > 9;

    if (g_twoCol)
    {
        int half = (st.count + 1) / 2;
        for (int r = 0; r < half; r++)
        {
            DrawItem(st, r, st.sel == r);
            int right = half + r;
            if (right < st.count)
                DrawItem(st, right, st.sel == right);
            else
                Out(L"%30s", L"");
            Out(L"\n");
        }
        g_rows = half;
    }
    else
    {
        for (int i = 0; i < st.count; i++)
        {
            DrawItem(st, i, st.sel == i);
            Out(L"\n");
        }
        g_rows = st.count;
    }
    Out(L"\n%s arrows/click/number, enter ok, esc exit%s\n",
        col::Dim, col::R);
}

static bool RowFromPoint(short y, short x, int& idx)
{
    int row = y - g_itemOrigin.Y;
    if (row < 0 || row >= g_rows)
        return false;
    idx = g_twoCol ? ((x >= g_midX ? g_rows : 0) + row) : row;
    return idx >= 0;
}

int RunMenu(const wchar_t* title, const MenuItem* items, int count)
{
    MenuState st;
    st.title = title;
    st.items = items;
    st.count = count;
    st.sel = 0;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    bool interactive = StdinIsConsole();

    DWORD oldMode = 0;
    if (interactive && hIn != INVALID_HANDLE_VALUE)
    {
        GetConsoleMode(hIn, &oldMode);
        SetConsoleMode(hIn, (g_cfg.mouse ? ENABLE_MOUSE_INPUT : 0) |
                                ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS |
                                ENABLE_PROCESSED_INPUT);
    }

    CONSOLE_SCREEN_BUFFER_INFO biStart;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &biStart);

    DrawAll(st);

    if (g_twoCol)
        g_midX = biStart.srWindow.Right / 2;

    Out(L"%s", col::HideCur);

    int result = -2;
    while (result == -2)
    {
        if (!interactive)
        {
            std::wstring c = Trim(PromptLine(L"choice> "));
            if (!IsAllDigits(c))
                break;
            wchar_t want = (wchar_t)(L'0' + wcstoul(c.c_str(), NULL, 10));
            for (int i = 0; i < count; i++)
                if (items[i].key == want)
                    result = i;
            if (result == -2)
                result = -1;
            break;
        }

        INPUT_RECORD rec[32];
        DWORD n = 0;
        if (!ReadConsoleInputW(hIn, rec, 32, &n) || n == 0)
        {
            result = -1;
            break;
        }
        for (DWORD k = 0; k < n && result == -2; k++)
        {
            if (rec[k].EventType == KEY_EVENT && rec[k].Event.KeyEvent.bKeyDown)
            {
                WORD vk = rec[k].Event.KeyEvent.wVirtualKeyCode;
                wchar_t ch = rec[k].Event.KeyEvent.uChar.AsciiChar;
                if (vk == VK_UP)
                    st.sel = (st.sel - 1 + count) % count;
                else if (vk == VK_DOWN || vk == VK_TAB)
                    st.sel = (st.sel + 1) % count;
                else if (vk == VK_RETURN)
                    result = st.sel;
                else if (vk == VK_ESCAPE)
                    result = -1;
                else if (ch >= L'0' && ch <= L'9')
                {
                    wchar_t want = ch;
                    for (int i = 0; i < count; i++)
                        if (items[i].key == want)
                        {
                            result = i;
                            break;
                        }
                }
                else
                    continue;
                DrawAll(st);
            }
            else if (rec[k].EventType == MOUSE_EVENT)
            {
                MOUSE_EVENT_RECORD& m = rec[k].Event.MouseEvent;
                if (m.dwEventFlags == MOUSE_MOVED)
                {
                    int idx;
                    if (RowFromPoint(m.dwMousePosition.Y, m.dwMousePosition.X, idx) &&
                        idx < count)
                    {
                        if (idx != st.sel)
                        {
                            st.sel = idx;
                            DrawAll(st);
                        }
                    }
                }
                else if ((m.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) &&
                         m.dwEventFlags != MOUSE_WHEELED &&
                         m.dwEventFlags != MOUSE_HWHEELED)
                {
                    int idx;
                    if (RowFromPoint(m.dwMousePosition.Y, m.dwMousePosition.X, idx) &&
                        idx < count)
                        result = idx;
                }
            }
        }
    }

    if (interactive && hIn != INVALID_HANDLE_VALUE)
        SetConsoleMode(hIn, oldMode);

    Out(L"%s", col::ShowCur);
    ClrScr();
    return result < 0 ? -1 : result;
}

