#pragma once
#include <windows.h>
#include <vector>

struct CfgBits
{
    bool colors;
    bool mouse;
    bool fontcheck;
    bool devmode;
};

extern CfgBits g_cfg;

void LoadSelfState();
void StartupCleanupSelf();
bool SaveCfg();
bool SelfWriteResource(const wchar_t* resName, const void* data, DWORD cb);
bool SelfDeleteResource(const wchar_t* resName);
bool SelfReadResource(const wchar_t* resName, std::vector<BYTE>& out);
