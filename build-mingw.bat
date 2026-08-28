@echo off
setlocal

REM Build helper for FIRI Unlocker using the MinGW-w64 w64devkit toolchain.
REM No MSVC/Visual Studio required. Provides bin\firiu.exe (admin manifest embedded).
REM Usage: build-mingw.bat

set W64DK=C:\Users\Andrew\AppData\Local\Temp\opencode\w64dk\w64devkit
set PATH=%W64DK%\bin;%PATH%

if not exist "obj" mkdir obj
if not exist "bin" mkdir bin

> obj\mgshim.h echo #ifndef MINGW_CFGMGR_SHIM_H
>>obj\mgshim.h echo #define MINGW_CFGMGR_SHIM_H
>>obj\mgshim.h echo.
>>obj\mgshim.h echo #ifndef PNP_VETO_TYPE
>>obj\mgshim.h echo typedef enum _PNP_VETO_TYPE {
>>obj\mgshim.h echo     PNP_VetoTypeUnknown, PNP_VetoLegacyDevice, PNP_VetoPendingClose,
>>obj\mgshim.h echo     PNP_VetoWindowsApp, PNP_VetoWindowsService, PNP_VetoOutstandingOpen,
>>obj\mgshim.h echo     PNP_VetoDevice, PNP_VetoDriver, PNP_VetoIllegalDeviceRequest,
>>obj\mgshim.h echo     PNP_VetoInsufficientPower, PNP_VetoNonDisableable, PNP_VetoLegacyDriver,
>>obj\mgshim.h echo     PNP_VetoInsufficientRights
>>obj\mgshim.h echo } PNP_VETO_TYPE;
>>obj\mgshim.h echo typedef PNP_VETO_TYPE ^*PPNP_VETO_TYPE;
>>obj\mgshim.h echo #endif
>>obj\mgshim.h echo.
>>obj\mgshim.h echo #ifndef CM_PROB_PHANTOM
>>obj\mgshim.h echo #define CM_PROB_PHANTOM       2
>>obj\mgshim.h echo #define CM_PROB_DISABLED      21
>>obj\mgshim.h echo #define CM_PROB_FAILED_START  25
>>obj\mgshim.h echo #endif
>>obj\mgshim.h echo #endif

echo [1/3] compiling...
set FAILED=
for %%f in (src\*.cpp) do g++ -std=c++17 -O2 -static -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00 -I src -include obj\mgshim.h -c "%%f" -o "obj\%%~nf.o" || set FAILED=1
if defined FAILED goto :fail

echo [2/3] embedding admin manifest...
> "%TEMP%\firiu.manifest" echo ^<?xml version="1.0" encoding="UTF-8" standalone="yes"?^>
>>"%TEMP%\firiu.manifest" echo ^<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"^>
>>"%TEMP%\firiu.manifest" echo   ^<assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="firiu" type="win32"/^>
>>"%TEMP%\firiu.manifest" echo   ^<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"^>
>>"%TEMP%\firiu.manifest" echo     ^<security^>
>>"%TEMP%\firiu.manifest" echo       ^<requestedPrivileges^>
>>"%TEMP%\firiu.manifest" echo         ^<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/^>
>>"%TEMP%\firiu.manifest" echo       ^</requestedPrivileges^>
>>"%TEMP%\firiu.manifest" echo     ^</security^>
>>"%TEMP%\firiu.manifest" echo   ^</trustInfo^>
>>"%TEMP%\firiu.manifest" echo   ^<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"^>
>>"%TEMP%\firiu.manifest" echo     ^<application^>
>>"%TEMP%\firiu.manifest" echo       ^<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/^>
>>"%TEMP%\firiu.manifest" echo     ^</application^>
>>"%TEMP%\firiu.manifest" echo   ^</compatibility^>
>>"%TEMP%\firiu.manifest" echo ^</assembly^>
set RCPATH=%TEMP%\firiu.manifest
set RCPATH2=%RCPATH:\=\\%
> "%TEMP%\firiu.rc" echo 1 24 "%RCPATH2%"
windres -O coff "%TEMP%\firiu.rc" -o obj\firiures.o || goto :fail

echo [3/3] linking...
g++ -static obj\*.o obj\firiures.o -o bin\firiu.exe -luser32 -ladvapi32 -lshell32 -lgdi32 -lcfgmgr32 -lole32 -loleaut32 -luuid -lwintrust -liphlpapi -lcrypt32 -lversion -lsetupapi || goto :fail

echo.
echo [OK] bin\firiu.exe built.
for %%F in (bin\firiu.exe) do echo   %%~zF bytes
endlocal
exit /b 0

:fail
echo.
echo [FAIL] Build failed. See errors above.
endlocal
exit /b 1
