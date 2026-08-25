#include "unlock.h"
#include <RestartManager.h>

typedef DWORD(WINAPI* FN_RmStartSession)(DWORD*, DWORD, wchar_t*);
typedef DWORD(WINAPI* FN_RmRegisterResources)(DWORD, UINT, LPCWSTR*, UINT,
                                              const RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
typedef DWORD(WINAPI* FN_RmGetList)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, DWORD*);
typedef DWORD(WINAPI* FN_RmShutdown)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK);
typedef DWORD(WINAPI* FN_RmEndSession)(DWORD);

static void ShowRmError(const wchar_t* what, DWORD code)
{
    Out(L"[!] %s failed (%lu)\n", what, (unsigned long)code);
}

void CmdUnlock(const std::wstring& pathArg, bool shutdownLockers)
{
    std::wstring path = pathArg;

    wchar_t full[MAX_PATH * 2];
    DWORD fn = GetFullPathNameW(path.c_str(), MAX_PATH * 2, full, NULL);
    if (fn > 0 && fn < MAX_PATH * 2)
        path.assign(full, fn);

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        LastErr(L"GetFileAttributesW");
        return;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        Out(L"[!] '%s' is a directory\n", path.c_str());
        return;
    }

    HMODULE rm = LoadLibraryW(L"rstrtmgr.dll");
    if (!rm)
    {
        Out(L"[!] Restart Manager not available in this environment "
            L"(very old WinPE?) - nothing to do\n");
        return;
    }

    FN_RmStartSession   pStart = (FN_RmStartSession)GetProcAddress(rm, "RmStartSession");
    FN_RmRegisterResources pReg = (FN_RmRegisterResources)GetProcAddress(rm, "RmRegisterResources");
    FN_RmGetList        pList  = (FN_RmGetList)GetProcAddress(rm, "RmGetList");
    FN_RmShutdown       pShut  = (FN_RmShutdown)GetProcAddress(rm, "RmShutdown");
    FN_RmEndSession     pEnd   = (FN_RmEndSession)GetProcAddress(rm, "RmEndSession");

    bool haveApi = pStart && pReg && pList && pShut && pEnd;
    if (!haveApi)
    {
        Out(L"[!] Restart Manager exports missing on this system\n");
        FreeLibrary(rm);
        return;
    }

    Out(L"[*] target: %s\n", path.c_str());

    DWORD session = 0;
    wchar_t key[CCH_RM_SESSION_KEY + 1];
    ZeroMemory(key, sizeof(key));
    DWORD err = pStart(&session, 0, key);
    if (err != ERROR_SUCCESS)
    {
        ShowRmError(L"RmStartSession", err);
        FreeLibrary(rm);
        return;
    }

    LPCWSTR docs[1] = { path.c_str() };
    err = pReg(session, 1, docs, 0, NULL, 0, NULL);
    if (err != ERROR_SUCCESS)
    {
        ShowRmError(L"RmRegisterResources", err);
        pEnd(session);
        FreeLibrary(rm);
        return;
    }

    UINT needed = 0, count = 0;
    DWORD reasons = 0;
    err = pList(session, &needed, &count, NULL, &reasons);

    std::vector<RM_PROCESS_INFO> apps;
    if (err == ERROR_MORE_DATA && needed > 0)
    {
        apps.resize(needed);
        count = needed;
        err = pList(session, &needed, &count, apps.data(), &reasons);
    }

    if (err != ERROR_SUCCESS)
    {
        ShowRmError(L"RmGetList", err);
    }
    else if (count == 0)
    {
        Out(L"[+] file is NOT locked by any process\n");
    }
    else
    {
        Out(L"[*] %u locking process(es):\n", (unsigned)count);
        for (UINT i = 0; i < count; i++)
        {
            RM_UNIQUE_PROCESS& u = apps[i].Process;
            Out(L"    [%u] PID %-7lu %-32s (short name: %s)\n",
                (unsigned)i, (unsigned long)u.dwProcessId,
                apps[i].strAppName, apps[i].strServiceShortName);
        }

        if (shutdownLockers)
        {
            err = pShut(session, RmForceShutdown, NULL);
            if (err == ERROR_SUCCESS)
                Out(L"[+] lockers shut down via Restart Manager\n");
            else
                ShowRmError(L"RmShutdown", err);
            Out(L"[*] re-checking...\n");
            UINT c2 = 0;
            UINT n2 = 0;
            DWORD r2 = 0;
            DWORD e2 = pList(session, &n2, &c2, NULL, &r2);
            if (e2 == ERROR_SUCCESS && c2 == 0)
                Out(L"[+] confirmed: file released\n");
            else if (e2 == ERROR_MORE_DATA)
                Out(L"[!] still locked by %u process(es)\n", (unsigned)n2);
        }
        else
        {
            Out(L"(report only; add -k or answer 'yes' in menu to shut lockers down)\n");
        }
    }

    pEnd(session);
    FreeLibrary(rm);
}
