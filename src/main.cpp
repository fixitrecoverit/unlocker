#include "common.h"
#include "procs.h"
#include "unlock.h"
#include "autoruns.h"
#include "repairs.h"
#include "hwinfo.h"
#include "filerestore.h"
#include "quickfixes.h"
#include "snapshots.h"
#include "handles.h"
#include "ads.h"
#include "net.h"
#include "cert.h"
#include "efi.h"
#include "mbr.h"
#include "triage.h"
#include "clip.h"
#include "watchdog.h"
#include "cfg.h"
#include "ui.h"
#include "modules.h"

static void CmdInfo()
{
    RTL_OSVERSIONINFOW vi;
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (nt)
    {
        typedef LONG(WINAPI * FN_RtlGetVersion)(PRTL_OSVERSIONINFOW);
        FN_RtlGetVersion f = (FN_RtlGetVersion)GetProcAddress(nt, "RtlGetVersion");
        if (f)
            f(&vi);
    }

    wchar_t comp[MAX_COMPUTERNAME_LENGTH + 2] = L"";
    wchar_t user[257] = L"";
    DWORD cl = MAX_COMPUTERNAME_LENGTH + 1, ul = 256;
    GetComputerNameW(comp, &cl);
    GetUserNameW(user, &ul);

    int bm = BootMode();

    Out(L"%swindows%s      %lu.%lu build %lu\n", col::Cyn, col::R,
        (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion,
        (unsigned long)vi.dwBuildNumber);
    Out(L"%spc / user%s     %s / %s\n", col::Cyn, col::R, comp, user);
    Out(L"%sboot%s          %s\n", col::Cyn, col::R,
        bm == 0 ? L"normal" : (bm == 1 ? L"safe mode" : L"winpe/winre"));
    Out(L"%sadmin%s         %s\n", col::Cyn, col::R,
        IsElevated() ? L"yes" : L"no");
    Out(L"%ssedebug%s       %s\n", col::Cyn, col::R,
        EnableDebugPriv() ? L"yes" : L"no");

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    Out(L"%sarch%s          proc %s / sys %s\n", col::Cyn, col::R,
        sizeof(void*) == 8 ? L"x64" : L"x86",
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
            ? L"x64"
            : (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64
                   ? L"arm64"
                   : L"x86"));

    if (!IsElevated())
        Out(L"%s[!] not admin - kill/unlock/repairs limited%s\n", col::Yel,
            col::R);

    Out(L"\n");
    PrintHardwareInfo();
}

static void CmdKillMenu()
{
    std::wstring t = PromptLine(L"pid or name> ");
    if (t.empty())
        return;
    EnableDebugPriv();
    if (IsAllDigits(t))
        KillPid((DWORD)wcstoul(t.c_str(), NULL, 10));
    else
        KillByName(t);
}

static void CmdUnlockMenu()
{
    std::wstring t = PromptLine(L"file path> ");
    if (t.empty())
        return;
    EnableDebugPriv();
    CmdUnlock(t, AskYN(L"kill what's holding it?"));
}

static void CmdSvcMenu()
{
    std::wstring t = PromptLine(L"service name> ");
    if (t.empty())
        return;
    DisableService(t, AskYN(L"delete it? (no=disable)"));
}

static void QuickFixesMenu()
{
    static const MenuItem items[] = {
        { '1', L"restore fonts" },
        { '2', L"force enable uac" },
        { '3', L"register FIRI Unlocker (win+r + cmd)" },
        { '4', L"reset hosts file" },
        { '5', L"disable internet proxy" },
        { '0', L"back" },
    };
    for (;;)
    {
        int pick = RunMenu(L"quick fixes", items, 6);
        if (pick < 0 || items[pick].key == '0')
            break;
        ClrScr();
        switch (items[pick].key)
        {
        case '1':
            QuickFixFonts(true);
            break;
        case '2':
            CmdForceUac();
            break;
        case '3':
            CmdInstallFiriu();
            break;
        case '4':
            CmdFixHosts();
            break;
        case '5':
            CmdFixProxy();
            break;
        }
        PauseEnter();
        ClrScr();
    }
}

static void SettingsMenu()
{
    static const MenuItem items[] = {
        { '1', L"colors" },
        { '2', L"mouse in menus" },
        { '3', L"font check at launch" },
        { 'm', L"modules (add / remove / view)" },
        { 'd', L"developer mode" },
        { '0', L"back" },
    };
    for (;;)
    {
        Out(L"\ncolors=%s  mouse=%s  fontcheck=%s  devmode=%s\n",
            g_cfg.colors ? L"on" : L"off",
            g_cfg.mouse ? L"on" : L"off",
            g_cfg.fontcheck ? L"on" : L"off",
            g_cfg.devmode ? L"on" : L"off");
        int pick = RunMenu(L"settings (saved inside FIRI Unlocker)", items, 6);
        if (pick < 0 || items[pick].key == '0')
            break;
        switch (items[pick].key)
        {
        case '1':
            g_cfg.colors = !g_cfg.colors;
            break;
        case '2':
            g_cfg.mouse = !g_cfg.mouse;
            break;
        case '3':
            g_cfg.fontcheck = !g_cfg.fontcheck;
            break;
        case 'm':
            ClrScr();
            CmdModules();
            ClrScr();
            continue;
        case 'd':
            ClrScr();
            CmdDevMode();
            ClrScr();
            continue;
        }
        SaveCfg();
        ClrScr();
    }
}

static void SnapshotsMenu()
{
    static const MenuItem items[] = {
        { '1', L"save snapshot now" },
        { '2', L"list snapshots" },
        { '3', L"diff vs scan now" },
        { '0', L"back" },
    };
    for (;;)
    {
        int pick = RunMenu(L"snapshots (stored in exe)", items, 4);
        if (pick < 0 || items[pick].key == '0')
            break;
        std::wstring name;
        if (items[pick].key != '2')
            name = PromptLine(L"name> ");
        ClrScr();
        switch (items[pick].key)
        {
        case '1':
            CmdSnapSave(name);
            break;
        case '2':
            CmdSnapList();
            break;
        case '3':
            CmdSnapDiff(name);
            break;
        }
        PauseEnter();
        ClrScr();
    }
}

static void MainLoop()
{
    static const MenuItem items[] = {
        { '1', L"system info" },
        { '2', L"processes" },
        { '3', L"kill process" },
        { '4', L"unlock file" },
        { '5', L"autoruns" },
        { '6', L"services" },
        { '7', L"service control" },
        { '8', L"file restorer" },
        { '9', L"quick fixes" },
        { 'q', L"restriction fix" },
        { 'w', L"ifeo watchdog" },
        { 'e', L"snapshots" },
        { 's', L"settings" },
        { 't', L"process tree" },
        { 'l', L"handle hunter" },
        { 'd', L"ads scanner" },
        { 'n', L"network table" },
        { 'f', L"efi partition check" },
        { 'b', L"mbr/boot signature check" },
        { 'g', L"triage wizard" },
        { 'c', L"clipboard sentry" },
        { 'm', L"modules" },
        { '0', L"exit" },
    };

    for (;;)
    {
        int pick = RunMenu(L"FIRI Unlocker", items, 23);
        if (pick < 0 || items[pick].key == '0')
            return;

        ClrScr();
        switch (items[pick].key)
        {
        case '1':
            CmdInfo();
            break;
        case '2':
            CmdPs(StdoutIsConsole());
            break;
        case '3':
            CmdKillMenu();
            break;
        case '4':
            CmdUnlockMenu();
            break;
        case '5':
            CmdAutoruns(AskYN(L"clean mode? (asks per item)"));
            break;
        case '6':
            CmdServices();
            break;
        case '7':
            CmdSvcMenu();
            break;
        case '8':
            CmdFileRestore();
            break;
        case '9':
            QuickFixesMenu();
            break;
        case 'q':
            CmdUnrestrict(AskYN(L"clean mode?"));
            break;
        case 'w':
            CmdWatchdog(AskYN(L"auto-remove new hijacks?"));
            break;
        case 'e':
            SnapshotsMenu();
            break;
        case 's':
            SettingsMenu();
            break;
        case 't':
            CmdTree();
            break;
        case 'l':
        {
            std::wstring p = PromptLine(L"file or folder> ");
            if (!p.empty())
                CmdHandles(p);
            break;
        }
        case 'd':
            CmdAds(L"");
            break;
        case 'n':
            CmdNet();
            break;
        case 'f':
            CmdEfiCheck();
            break;
        case 'b':
            CmdMbr(L"");
            break;
        case 'g':
            CmdTriageWizard();
            break;
        case 'c':
            ClrScr();
            CmdClipSentry();
            break;
        case 'm':
            ClrScr();
            CmdModules();
            break;
        }

        PauseEnter();
        ClrScr();
    }
}

static void Help()
{
    Out(L"usage: FIRI Unlocker [command]\n\n"
        L"  info              system + hardware summary\n"
        L"  ps                live process view\n"
        L"  kill <pid|name>   terminate\n"
        L"  unlock <file> [-k] show/kill file locks\n"
        L"  autoruns [clean]  persistence scan/clean (sig-checked)\n"
        L"  services          service list\n"
        L"  svc-disable|svc-delete <name>\n"
        L"  restore-files     system file check vs winsxs\n"
        L"  fix-fonts         font repair\n"
        L"  fix-hosts         reset hosts file to defaults\n"
        L"  fix-proxy         disable wininet proxy / autoconfig url\n"
        L"  force-uac         re-enable uac\n"
        L"  install-firiu     win+r/cmd integration\n"
        L"  unrestrict [clean] ifeo debuggers + policy restrictions\n"
        L"  watchdog [--auto-clean] alert on new ifeo hijacks\n"
        L"  snap-save|snap-list|snap-diff <name>\n"
        L"  settings [colors|mouse|fontcheck on|off]\n"
        L"  tree              process parent/child tree\n"
        L"  handles <path>    who holds a handle to it\n"
        L"  ads [path]        alternate data stream scan\n"
        L"  net               tcp/udp per-process table\n"
        L"  efi               efi system partition signature check\n"
        L"  mbr [path]        bootloader/OS pick by file name+size\n"
        L"  triage            review autoruns, store keep/danger verdicts\n"
        L"  triage-check      list currently active flagged items\n"
        L"  triage-reset      clear stored verdicts\n"
        L"  clipsentry        beep on clipboard changes\n"
        L"  modules           module list / add / remove / view\n"
        L"  module-add <path> embed a .firiumodule into FIRI Unlocker\n"
        L"  module-remove <id> remove a module from FIRI Unlocker\n"
        L"  devmode on|off    developer mode (removes all restrictions)\n");
}

int ExecCli(int argc, LPWSTR* argv)
{
    std::wstring cmd = Lower(argv[1]);
    int rc = 0;

    if (cmd == L"help" || cmd == L"/?" || cmd == L"-h")
        Help();
    else if (cmd == L"info")
        CmdInfo();
    else if (cmd == L"ps")
        CmdPs(false);
    else if (cmd == L"kill")
    {
        EnableDebugPriv();
        for (int i = 2; i < argc; i++)
        {
            std::wstring t = Trim(argv[i]);
            if (IsAllDigits(t))
                KillPid((DWORD)wcstoul(t.c_str(), NULL, 10));
            else if (!t.empty())
                KillByName(t);
        }
    }
    else if (cmd == L"unlock")
    {
        std::wstring path;
        bool shut = false;
        for (int i = 2; i < argc; i++)
        {
            if (wcscmp(argv[i], L"-k") == 0)
                shut = true;
            else if (path.empty())
                path = argv[i];
        }
        if (path.empty())
        {
            Help();
            rc = 2;
        }
        else
        {
            EnableDebugPriv();
            CmdUnlock(path, shut);
        }
    }
    else if (cmd == L"autoruns")
        CmdAutoruns(argc >= 3 && wcscmp(argv[2], L"clean") == 0);
    else if (cmd == L"services")
        CmdServices();
    else if (cmd == L"svc-disable" || cmd == L"svc-delete")
    {
        if (argc < 3)
            rc = 2;
        else
            DisableService(argv[2], cmd == L"svc-delete");
    }
    else if (cmd == L"restore-files")
        CmdFileRestore();
    else if (cmd == L"fix-fonts")
        QuickFixFonts(true);
    else if (cmd == L"fix-hosts")
        CmdFixHosts();
    else if (cmd == L"fix-proxy")
        CmdFixProxy();
    else if (cmd == L"force-uac")
        CmdForceUac();
    else if (cmd == L"install-firiu")
        CmdInstallFiriu();
    else if (cmd == L"unrestrict")
        CmdUnrestrict(argc >= 3 && wcscmp(argv[2], L"clean") == 0);
    else if (cmd == L"tree")
        CmdTree();
    else if (cmd == L"handles")
    {
        if (argc < 3)
            rc = 2;
        else
            CmdHandles(argv[2]);
    }
    else if (cmd == L"ads")
        CmdAds(argc >= 3 ? argv[2] : L"");
    else if (cmd == L"net")
        CmdNet();
    else if (cmd == L"efi")
        CmdEfiCheck();
    else if (cmd == L"mbr")
        CmdMbr(argc >= 3 ? argv[2] : L"");
    else if (cmd == L"triage" || cmd == L"triage-wizard")
        CmdTriageWizard();
    else if (cmd == L"triage-check")
        CmdTriageCheck();
    else if (cmd == L"triage-reset")
        CmdTriageReset();
    else if (cmd == L"clipsentry")
        CmdClipSentry();
    else if (cmd == L"watchdog")
    {
        bool ac = false;
        for (int i = 2; i < argc; i++)
            if (wcscmp(argv[i], L"--auto-clean") == 0 ||
                wcscmp(argv[i], L"-a") == 0)
                ac = true;
        CmdWatchdog(ac);
    }
    else if (cmd == L"snap-save")
        CmdSnapSave(argc >= 3 ? argv[2] : L"");
    else if (cmd == L"snap-list")
        CmdSnapList();
    else if (cmd == L"snap-diff")
        CmdSnapDiff(argc >= 3 ? argv[2] : L"");
    else if (cmd == L"modules")
        CmdModules();
    else if (cmd == L"module-add")
    {
        if (argc < 3)
            rc = 2;
        else
            AddModuleFile(argv[2]);
    }
    else if (cmd == L"module-remove")
    {
        if (argc < 3)
            rc = 2;
        else
            RemoveModule(argv[2]);
    }
    else if (cmd == L"devmode")
    {
        std::wstring how = argc >= 3 ? Lower(argv[2]) : L"";
        if (how != L"on" && how != L"off")
            rc = 2;
        else
        {
            g_cfg.devmode = how == L"on";
            SaveCfg();
            Out(L"devmode=%s\n", g_cfg.devmode ? L"on" : L"off");
        }
    }
    else if (cmd == L"settings")
    {
        for (int i = 2; i + 1 < argc; i += 2)
        {
            std::wstring what = Lower(argv[i]);
            std::wstring how = Lower(argv[i + 1]);
            bool on = how == L"on";
            if (what == L"colors")
                g_cfg.colors = on;
            else if (what == L"mouse")
                g_cfg.mouse = on;
            else if (what == L"fontcheck")
                g_cfg.fontcheck = on;
            else if (what == L"devmode")
                g_cfg.devmode = on;
        }
        Out(L"colors=%s mouse=%s fontcheck=%s devmode=%s\n",
            g_cfg.colors ? L"on" : L"off",
            g_cfg.mouse ? L"on" : L"off",
            g_cfg.fontcheck ? L"on" : L"off",
            g_cfg.devmode ? L"on" : L"off");
        SaveCfg();
    }
    else
    {
        Out(L"%s[!]%s unknown '%s'\n", col::Red, col::R, argv[1]);
        Help();
        rc = 2;
    }

    return rc;
}

int main()
{
    InitConsole();
    LoadSelfState();
    g_colorsOff = !g_cfg.colors;
    StartupCleanupSelf();
    InitModules();

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return 1;

    if (argc >= 2)
    {
        int rc = ExecCli(argc, argv);
        LocalFree(argv);
        return rc;
    }

    Out(L"%schecking fonts...%s\n", col::Dim, col::R);
    if (g_cfg.fontcheck)
    {
        int fixed = QuickFixFonts(false);
        if (fixed > 0)
        {
            Out(L"%s[+]%s repaired %d font issue(s)\n", col::Grn, col::R,
                fixed);
            Sleep(1200);
        }
    }

    if (BootMode() == 0)
        StartupCertCheck();

    MainLoop();
    LocalFree(argv);
    return 0;
}

