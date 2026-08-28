#pragma once
#include "common.h"

void CmdAutoruns(bool clean);
void CmdServices();
bool DisableService(const std::wstring& name, bool deleteIt);
