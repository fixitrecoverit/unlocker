#pragma once
#include "common.h"
#include <map>
#include <vector>

typedef std::map<std::wstring, std::vector<std::wstring> > StoreMap;

void CmdFileRestore();

std::wstring LowerCopy(std::wstring s);

bool ScanWinSxS(StoreMap& found, const std::vector<std::wstring>& names);
