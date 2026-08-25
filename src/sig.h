#pragma once
#include <string>

int VerifyFileSig(const std::wstring& file);
const wchar_t* SigTagForCommand(const std::wstring& cmdlineRaw);
