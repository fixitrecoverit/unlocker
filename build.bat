@echo off
REM Build helper for FIRI Unlocker (MSVC). Run from an "x64 Native Tools" command prompt.
setlocal

set OBJDIR=obj
set BINDIR=bin

if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if not exist "%BINDIR%" mkdir "%BINDIR%"

if not defined VSCMD_ARG_TGT_ARCH (
    echo [ERROR] This script must be run from a "x64 Native Tools" ^(VS Developer^) prompt.
    echo         Open "x64 Native Tools Command Prompt for VS 2022" and re-run.
    exit /b 1
)

cl /nologo /W4 /EHsc /O2 /MT /D_UNICODE /DUNICODE /Fo%OBJDIR%\ /Fe%BINDIR%\firiu.exe src\*.cpp ^
   /link /SUBSYSTEM:CONSOLE ^
   /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" ^
   user32.lib advapi32.lib shell32.lib gdi32.lib cfgmgr32.lib ^
   ole32.lib oleaut32.lib uuid.lib wintrust.lib iphlpapi.lib crypt32.lib

if errorlevel 1 (
    echo.
    echo [FAIL] Compilation failed.
    exit /b 1
)
echo.
echo [OK] bin\firiu.exe built.
endlocal
