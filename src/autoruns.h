#pragma once
#include "common.h"

void CmdAutoruns(bool clean);
void CmdWatchdog(bool autoclean);
void CmdServices();
bool DisableService(const std::wstring& name, bool deleteIt);
