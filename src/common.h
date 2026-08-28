#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

extern const wchar_t* kVersion;

struct CfgBits;
extern bool g_colorsOff;

namespace col
{
extern const wchar_t *R, *Dim, *Red, *Grn, *Yel, *Cyn, *Wht, *Inv,
    *HideCur, *ShowCur, *Sel;
}

extern std::vector<std::wstring>* g_capture;

void InitConsole();
void ClrScr();
void PauseEnter();

void Out(const wchar_t* fmt, ...);
void LastErr(const wchar_t* what);

bool StdoutIsConsole();
bool StdinIsConsole();
bool IsElevated();
bool EnableDebugPriv();
bool EnablePrivByName(const wchar_t* name);
bool IsSafeMode(int* kind);
int BootMode();
std::wstring SysDir();
std::wstring WinDir();
std::wstring SelfPath();

std::wstring Lower(const std::wstring& s);
std::wstring Trim(const wchar_t* s);
std::wstring Trim(const std::wstring& s);
bool IsAllDigits(const std::wstring& s);
void SplitLines(const std::wstring& text, std::vector<std::wstring>& lines);
std::wstring PromptLine(const wchar_t* label);
bool AskYN(const wchar_t* question);
bool AskYNDef(const wchar_t* question);
bool WaitKeys(DWORD (*match)(const KEY_EVENT_RECORD& ke));
void FlushStdin();
