# FIRI Unlocker

**FIRI Unlocker** is a portable Windows remediation utility distributed as a single static executable.
It combines persistence scanning, process/file inspection and system repair in one tool, runs from
regular sessions as well as Safe Mode / WinPE / WinRE, and requires no installation.

> [!CAUTION]
> Microsoft Defender and other antivirus products may flag FIRI Unlocker as malicious.
> This is a false positive: the tool accesses, replaces and edits system files, terminates processes,
> modifies registry values and always runs with administrator rights — behavior that heuristic engines
> classify as risky. **FIRI Unlocker is not a virus.** The code is fully open source; anyone can view,
> audit, modify and build every FIRI Project tool themselves. Original signed builds are always available
> in the [GitHub Releases](../../releases) page.

## Features

- Persistence scanner covering ~25 autorun locations (both 64-bit and WOW64 registry views), with
  Authenticode + catalog signature verification on every referenced binary (`[signed]` / `[UNSIGNED]` /
  `[BAD-SIG]` / `[missing]`)
- Guided cleanup mode, IFEO hijack watchdog daemon, interactive triage wizard with persistent verdicts
- Process management: live list, kill by PID/name, parent→child tree
- File unlocker backed by kernel handle-table enumeration ("which process holds this file?")
- Per-process TCP/UDP network table
- NTFS alternate data stream scanner (hotspot folders or custom path)
- EFI System Partition mount + signature audit
- Clipboard monitoring daemon
- System file restore from WinSxS, font repair, UAC re-enable, Explorer/CMD policy unrestrict
- Autorun snapshots stored inside the executable; settings likewise (no registry/files)
- Single-file deployment: static CRT, embedded admin manifest, works offline

## Building

Requirements: Visual Studio Build Tools 2022 or newer (MSVC v143+, Windows SDK 10), x64 Native Tools
command prompt.

Compile:

```bat
cl /nologo /W4 /EHsc /O2 /MT /D_UNICODE /DUNICODE /Foobj\ /Febin\firiu.exe src\*.cpp ^
   /link /SUBSYSTEM:CONSOLE ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   user32.lib advapi32.lib shell32.lib gdi32.lib cfgmgr32.lib ^
   ole32.lib oleaut32.lib uuid.lib wintrust.lib iphlpapi.lib crypt32.lib
```

The `obj\` directory is intermediate output only and can be deleted after linking.

### Code signing (optional)

Place `FIRI_Project.pfx` at the repository root and sign the produced binary:

```bat
signtool sign /fd SHA256 /f FIRI_Project.pfx /p <certificate password> bin\firiu.exe
```

Signing removes the SmartScreen warning on end-user machines when the certificate is trusted.
On first launch the program offers to install its certificate into the Local Machine trust stores
(Trusted Publishers and Trusted Root); this prompt appears only in classic Windows, not in WinPE/WinRE.

## Repository layout

```
firiu/
├─ src/
│  ├─ main.cpp              entry point, CLI dispatch, menus
│  ├─ common.cpp/.h         console foundation, colors, boot-mode detection
│  ├─ autoruns.cpp/.h       exhaustive persistence scanner
│  ├─ repairs.cpp/.h        IFEO/policy restriction sweep
│  ├─ watchdog.cpp          IFEO change-monitor daemon
│  ├─ triage.cpp/.h         keep/dangerous verdict storage + wizard
│  ├─ snapshots.cpp/.h      autorun snapshots (in-exe resource)
│  ├─ procs.cpp/.h          process list/kill/tree
│  ├─ handles.cpp/.h        kernel handle hunter
│  ├─ net.cpp/.h            per-process TCP/UDP table
│  ├─ ads.cpp/.h            alternate data stream scanner
│  ├─ efi.cpp/.h            EFI partition check
│  ├─ cert.cpp/.h           certificate install prompt
│  ├─ sig.cpp/.h            Authenticode + catalog verification
│  ├─ filerestore.cpp/.h    system file verification vs WinSxS
│  ├─ quickfixes.cpp/.h     fonts, UAC, shell integration fixes
│  ├─ hwinfo.cpp/.h         hardware summary
│  ├─ unlock.cpp/.h         file lock resolution
│  ├─ clip.cpp/.h           clipboard sentry daemon
│  ├─ cfg.cpp/.h            self-contained configuration
│  └─ ui.cpp/.h             TUI menu renderer
├─ README.md
├─ README_ru.md
└─ .gitignore
```

## Disclaimer

FIRI Unlocker modifies running systems. Use it only if you understand what each action does.
The software is provided "as is", without warranty of any kind.
