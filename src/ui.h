#pragma once
#include "common.h"

struct MenuItem
{
    wchar_t key;
    const wchar_t* label;
    bool disabled;
};

int RunMenu(const wchar_t* title, const MenuItem* items, int count);
