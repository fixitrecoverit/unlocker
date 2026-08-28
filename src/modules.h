#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "firi_api.h"

struct ModuleButton
{
    std::wstring tab;
    std::wstring label;
    FiriModuleFn cb;
};

struct ModuleInst
{
    std::wstring id;
    std::wstring name;
    std::wstring version;
    std::wstring author;
    std::vector<std::pair<std::wstring, std::wstring>> labels;
    DWORD caps;         /* declared in meta */
    DWORD capsDetected; /* from import scan */
    DWORD flags;        /* FIRI_META_FLAG_* */
    bool builtin;
    bool loaded;
    std::wstring loadError;

    /* mapped image (third-party modules only) */
    std::vector<BYTE> raw;
    std::vector<BYTE> image;
    PBYTE base;
    FARPROC entryPoint; /* DllMain-style CRT entry (NULL if none) */
    FiriModuleEntryFn entry;
    FiriModuleFn run;

    std::vector<std::wstring> tabs;
    std::vector<ModuleButton> buttons;
};

void InitModules();
void CmdModules();

void CmdModuleAdd(const std::wstring& path);
bool AddModuleFile(const std::wstring& path);
void CmdModuleRemove(const std::wstring& id);
bool RemoveModule(const std::wstring& id);

void CmdDevMode();
bool IsDevMode();

int ExecCli(int argc, LPWSTR* argv); /* defined in main.cpp */

const wchar_t* CapName(DWORD bit);
std::wstring CapsList(DWORD caps);