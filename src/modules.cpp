#include "modules.h"
#include "common.h"
#include "cfg.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>
#include <algorithm>

/* ------------------------------------------------------------------ */
/* PE helpers                                                          */
/* ------------------------------------------------------------------ */

static PIMAGE_NT_HEADERS PeNt(const std::vector<BYTE>& raw)
{
    if (raw.size() < sizeof(IMAGE_DOS_HEADER))
        return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    if (dos->e_lfanew <= 0 ||
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > raw.size())
        return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    return nt;
}

static DWORD RvaToFile(PIMAGE_NT_HEADERS nt, DWORD rva)
{
    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return rva;
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
    {
        DWORD va = s->VirtualAddress;
        DWORD sz = (std::max)(s->SizeOfRawData, s->Misc.VirtualSize);
        if (rva >= va && rva < va + sz)
            return s->PointerToRawData + (rva - va);
    }
    return 0;
}

static bool EntrySubDir(IMAGE_RESOURCE_DIRECTORY_ENTRY* e, DWORD& out)
{
    if (e->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
    {
        out = e->OffsetToData & 0x7FFFFFFF;
        return true;
    }
    return false;
}

static bool FindNamedRcData(PIMAGE_NT_HEADERS nt,
                            const std::vector<BYTE>& raw, const wchar_t* want,
                            DWORD& outRva, DWORD& outSize)
{
    DWORD resRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
                       .VirtualAddress;
    if (!resRva)
        return false;
    DWORD tOff = RvaToFile(nt, resRva);
    if (!tOff || tOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > raw.size())
        return false;

    IMAGE_RESOURCE_DIRECTORY* tdir =
        (IMAGE_RESOURCE_DIRECTORY*)(raw.data() + tOff);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY te =
        (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(tdir + 1);
    for (WORD i = 0; i < tdir->NumberOfIdEntries; i++, te++)
    {
        if (te->Name & IMAGE_RESOURCE_NAME_IS_STRING)
            continue;
        if ((DWORD)te->Id != 10)
            continue;
        DWORD nameDirRva = 0;
        if (!EntrySubDir(te, nameDirRva))
            continue;
        nameDirRva += resRva;
        DWORD no = RvaToFile(nt, nameDirRva);
        if (!no || no + sizeof(IMAGE_RESOURCE_DIRECTORY) > raw.size())
            continue;
        IMAGE_RESOURCE_DIRECTORY* nd =
            (IMAGE_RESOURCE_DIRECTORY*)(raw.data() + no);
        PIMAGE_RESOURCE_DIRECTORY_ENTRY ne =
            (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nd + 1);
        for (WORD j = 0; j < nd->NumberOfNamedEntries + nd->NumberOfIdEntries;
             j++, ne++)
        {
            bool match = false;
            if (ne->Name & IMAGE_RESOURCE_NAME_IS_STRING)
            {
                DWORD soff = RvaToFile(nt, resRva + (ne->Name & 0x7FFFFFFF));
                if (soff && soff + 2 <= raw.size())
                {
                    WORD len = *(WORD*)(raw.data() + soff);
                    if (soff + 2 + (DWORD)len * 2 <= raw.size())
                    {
                        std::wstring nm((const wchar_t*)(raw.data() + soff + 2),
                                        len);
                        if (_wcsicmp(nm.c_str(), want) == 0)
                            match = true;
                    }
                }
            }
            if (!match)
                continue;
            /* language level: entry offsets are relative to the root
             * resource directory, not the enclosing directory */
            DWORD langSelf = ne->OffsetToData & 0x7FFFFFFF;
            DWORD langRva = resRva + langSelf;
            DWORD lo = RvaToFile(nt, langRva);
            if (!lo || lo + sizeof(IMAGE_RESOURCE_DIRECTORY) > raw.size())
                return false;
            IMAGE_RESOURCE_DIRECTORY* ld =
                (IMAGE_RESOURCE_DIRECTORY*)(raw.data() + lo);
            PIMAGE_RESOURCE_DIRECTORY_ENTRY le =
                (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ld + 1);
            for (WORD k = 0;
                 k < ld->NumberOfNamedEntries + ld->NumberOfIdEntries;
                 k++, le++)
            {
                if (le->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
                    continue;
                DWORD dataSelf = le->OffsetToData & 0x7FFFFFFF;
                DWORD dataRva2 = resRva + dataSelf;
                DWORD doff = RvaToFile(nt, dataRva2);
                if (!doff ||
                    doff + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > raw.size())
                    continue;
                IMAGE_RESOURCE_DATA_ENTRY* de =
                    (IMAGE_RESOURCE_DATA_ENTRY*)(raw.data() + doff);
                outRva = de->OffsetToData;
                outSize = de->Size;
                return true;
            }
            return false;
        }
        break;
    }
    return false;
}

static bool ExtractResourceData(const std::vector<BYTE>& raw,
                                const wchar_t* want, std::vector<BYTE>& out)
{
    PIMAGE_NT_HEADERS nt = PeNt(raw);
    if (!nt)
        return false;
    DWORD rva = 0, sz = 0;
    if (!FindNamedRcData(nt, raw, want, rva, sz))
        return false;
    DWORD off = RvaToFile(nt, rva);
    if (!off || off + sz > raw.size())
        return false;
    out.assign(raw.begin() + off, raw.begin() + off + sz);
    return true;
}

static std::wstring Utf8Bytes(const BYTE* p, size_t n)
{
    if (!n)
        return std::wstring();
    int need = MultiByteToWideChar(CP_UTF8, 0, (const char*)p, (int)n, NULL, 0);
    if (need <= 0)
        return std::wstring();
    std::wstring out((size_t)need, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, (const char*)p, (int)n, &out[0], need);
    return out;
}

static void* LookupExport(PBYTE base, const char* want);

/* in-memory PE mapper: maps the module image, fixes relocations, resolves
 * imports against already-loaded system DLLs, returns the mapped base. */
static PBYTE MapModuleInMemory(const std::vector<BYTE>& raw, FARPROC& dllEntry)
{
    dllEntry = NULL;
    PIMAGE_NT_HEADERS nt = PeNt(raw);
    if (!nt)
        return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        sizeof(void*) != 8)
        return NULL;
    SIZE_T sz = nt->OptionalHeader.SizeOfImage;
    if (!sz || sz > (1u << 26))
        return NULL;

    PBYTE base = (PBYTE)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!base)
        return NULL;

    SIZE_T head = (std::min)((SIZE_T)nt->OptionalHeader.SizeOfHeaders,
                             raw.size());
    memcpy(base, raw.data(), head);

    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
    {
        DWORD va = s->VirtualAddress, ro = s->PointerToRawData,
              rs = s->SizeOfRawData;
        if (ro > raw.size())
            continue;
        if (rs > raw.size() - ro)
            rs = (DWORD)raw.size() - ro;
        if (va + rs <= sz)
            memcpy(base + va, raw.data() + ro, rs);
    }

    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    DWORD relRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                       .VirtualAddress;
    DWORD relSz = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                      .Size;
    if (relRva && relSz && delta)
    {
        PBYTE p = base + relRva, pe = base + relRva + relSz;
        while (p + sizeof(IMAGE_BASE_RELOCATION) <= pe)
        {
            IMAGE_BASE_RELOCATION* b = (IMAGE_BASE_RELOCATION*)p;
            if (!b->SizeOfBlock || b->SizeOfBlock < 8)
                break;
            DWORD n = (b->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* items = (WORD*)(p + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < n; i++)
            {
                WORD type = (WORD)((items[i] >> 12) & 0xF);
                DWORD off = items[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64)
                    *(ULONGLONG*)(base + b->VirtualAddress + off) += delta;
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(base + b->VirtualAddress + off) += (DWORD)delta;
            }
            p += b->SizeOfBlock;
        }
    }

    DWORD impRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                       .VirtualAddress;
    if (impRva)
    {
        IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(base + impRva);
        for (; d->Name; d++)
        {
            const char* nm = (const char*)(base + d->Name);
            wchar_t w[512];
            MultiByteToWideChar(CP_ACP, 0, nm, -1, w, 512);
            HMODULE h = GetModuleHandleW(w);
            if (!h)
                h = LoadLibraryW(w);
            if (!h)
            {
                VirtualFree(base, 0, MEM_RELEASE);
                return NULL;
            }
            PIMAGE_THUNK_DATA64 o =
                d->OriginalFirstThunk
                    ? (PIMAGE_THUNK_DATA64)(base + d->OriginalFirstThunk)
                    : NULL;
            PIMAGE_THUNK_DATA64 t = (PIMAGE_THUNK_DATA64)(base + d->FirstThunk);
            for (; o ? o->u1.AddressOfData : t->u1.AddressOfData;
                 o = o ? o + 1 : NULL, t++)
            {
                UINT_PTR imp = o ? o->u1.AddressOfData : t->u1.AddressOfData;
                if (o && (imp & IMAGE_ORDINAL_FLAG64))
                    t->u1.Function =
                        (ULONGLONG)GetProcAddress(h, (LPCSTR)(imp & 0xFFFF));
                else
                {
                    PIMAGE_IMPORT_BY_NAME ib =
                        (PIMAGE_IMPORT_BY_NAME)(base + imp);
                    t->u1.Function = (ULONGLONG)GetProcAddress(h, ib->Name);
                }
                if (!t->u1.Function)
                {
                    VirtualFree(base, 0, MEM_RELEASE);
                    return NULL;
                }
            }
        }
    }

    dllEntry = nt->OptionalHeader.AddressOfEntryPoint
                   ? (FARPROC)(base + nt->OptionalHeader.AddressOfEntryPoint)
                   : NULL;
    return base;
}

static void* LookupExport(PBYTE base, const char* want)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    if (!expRva)
        return NULL;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(base + expRva);
    DWORD* names = (DWORD*)(base + e->AddressOfNames);
    WORD* ords = (WORD*)(base + e->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfNames; i++)
    {
        const char* n = (const char*)(base + names[i]);
        if (strcmp(n, want) == 0)
            return (void*)(base + funcs[ords[i]]);
    }
    return NULL;
}

/* ---------------- import scanning (capability detection) ----------- */

static void LowerCopy(char* out, size_t cap, const char* in)
{
    size_t i = 0;
    while (in[i] && i + 1 < cap)
    {
        out[i] = (char)tolower((unsigned char)in[i]);
        i++;
    }
    out[i] = 0;
}

static bool S(const char* s, const char* p)
{
    return _strnicmp(s, p, strlen(p)) == 0;
}

static DWORD ClassifyImport(const char* dll, const char* fn)
{
    DWORD c = 0;
    char f[256], d[256];
    LowerCopy(f, sizeof(f), fn);
    LowerCopy(d, sizeof(d), dll);

    if (strstr(d, "ws2_32") || strstr(d, "wininet") || strstr(d, "winhttp") ||
        strstr(d, "urlmon") || strstr(d, "dnsapi") || strstr(d, "mswsock"))
        c |= FIRI_CAP_NETWORK;

    if (S(f, "reg"))
        c |= FIRI_CAP_REGISTRY;
    if (strstr(f, "regset") || strstr(f, "regcreate") ||
        strstr(f, "regdelete") || strstr(f, "regloadkey") ||
        strstr(f, "ntcreatekey") || strstr(f, "ntopenkey") ||
        strstr(f, "zwcreatekey"))
        c |= FIRI_CAP_REGISTRY;

    if (S(f, "deletefile") || S(f, "createdirectory") ||
        S(f, "removedirectory") || S(f, "movefile") || S(f, "replacefile") ||
        S(f, "copyfile") || S(f, "writefile") || S(f, "setfileattributes") ||
        S(f, "ntdeletefile") || S(f, "zwdeletefile") || S(f, "createfile"))
        c |= FIRI_CAP_FILE;

    if (strstr(f, "createprocess") || S(f, "shellexecute") || S(f, "winexec") ||
        strstr(f, "writeprocessmemory") || strstr(f, "readprocessmemory") ||
        strstr(f, "virtualallocex") || S(f, "createremotethread") ||
        strstr(f, "ntcreatethreadex") || S(f, "queueuserapc") ||
        strstr(f, "setwindowshookex"))
        c |= FIRI_CAP_PROCESS;

    if (S(f, "deviceiocontrol") || S(f, "lockfileex"))
        c |= FIRI_CAP_DISK;

    if (S(f, "openscmanager") || strstr(f, "createservice") ||
        strstr(f, "changeserviceconfig") || S(f, "deleteservice") ||
        S(f, "startservice") || S(f, "controlservice"))
        c |= FIRI_CAP_SERVICE;

    if (S(f, "openclipboard") || S(f, "setclipboarddata") ||
        S(f, "getclipboarddata") || S(f, "emptyclipboard") ||
        S(f, "addclipboardformatlistener"))
        c |= FIRI_CAP_CLIPBOARD;

    if (S(f, "registerhotkey") || S(f, "getasynckeystate") ||
        S(f, "keybd_event") || S(f, "mouse_event") || S(f, "sendinput"))
        c |= FIRI_CAP_MONITOR;

    return c;
}

static DWORD ScanImports(const std::vector<BYTE>& raw)
{
    PIMAGE_NT_HEADERS nt = PeNt(raw);
    if (!nt || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;
    DWORD impRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                       .VirtualAddress;
    DWORD caps = 0;
    if (!impRva)
        return caps;

    DWORD off = RvaToFile(nt, impRva);
    while (off && off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= raw.size())
    {
        IMAGE_IMPORT_DESCRIPTOR* d =
            (IMAGE_IMPORT_DESCRIPTOR*)(raw.data() + off);
        if (!d->Name)
            break;
        DWORD noff = RvaToFile(nt, d->Name);
        char dll[512] = "";
        if (noff)
        {
            size_t k = 0;
            while (noff + k < raw.size() && k < 511 && raw[noff + k])
            {
                dll[k] = (char)raw[noff + k];
                k++;
            }
            dll[k] = 0;
        }
        if (d->OriginalFirstThunk)
        {
            DWORD itOff = RvaToFile(nt, d->OriginalFirstThunk);
            while (itOff && itOff + sizeof(IMAGE_THUNK_DATA64) <= raw.size())
            {
                IMAGE_THUNK_DATA64* th =
                    (IMAGE_THUNK_DATA64*)(raw.data() + itOff);
                UINT_PTR imp = th->u1.AddressOfData;
                if (!imp)
                    break;
                char fn[512] = "";
                if (imp & IMAGE_ORDINAL_FLAG64)
                {
                    char b[24];
                    wsprintfA(b, "#%u", (unsigned)(imp & 0xFFFF));
                    strcpy(fn, b);
                }
                else
                {
                    DWORD fo = RvaToFile(nt, (DWORD)(imp & 0x7FFFFFFF));
                    if (fo && fo + 2 < raw.size())
                    {
                        size_t q = fo + 2, w = 0;
                        while (q < raw.size() && w < 511 && raw[q])
                            fn[w++] = (char)raw[q++];
                        fn[w] = 0;
                    }
                }
                caps |= ClassifyImport(dll, fn);
                itOff += sizeof(IMAGE_THUNK_DATA64);
            }
        }
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return caps;
}

/* ---------------- module registry ---------------------------------- */

static std::vector<ModuleInst> g_mods;
static ModuleInst* g_ctx = NULL;
static FiriApi g_api;
static std::wstring g_promptBuf;

const wchar_t* CapName(DWORD bit)
{
    switch (bit)
    {
    case FIRI_CAP_REGISTRY:  return L"registry";
    case FIRI_CAP_FILE:      return L"file";
    case FIRI_CAP_NETWORK:   return L"network";
    case FIRI_CAP_PROCESS:   return L"process";
    case FIRI_CAP_DISK:      return L"disk";
    case FIRI_CAP_SERVICE:   return L"service";
    case FIRI_CAP_CLIPBOARD: return L"clipboard";
    case FIRI_CAP_MONITOR:   return L"monitor";
    default:
        return L"?";
    }
}

std::wstring CapsList(DWORD caps)
{
    std::wstring s;
    for (DWORD bit = FIRI_CAP_REGISTRY; bit <= FIRI_CAP_MONITOR; bit <<= 1)
    {
        if (caps & bit)
        {
            if (!s.empty())
                s += L", ";
            s += CapName(bit);
        }
    }
    if (s.empty())
        s = L"none";
    return s;
}

static const wchar_t* CapWarning(DWORD bit)
{
    switch (bit)
    {
    case FIRI_CAP_REGISTRY:
        return L"accesses the Windows registry (HKLM/HKCU)";
    case FIRI_CAP_FILE:
        return L"creates, overwrites or deletes files";
    case FIRI_CAP_NETWORK:
        return L"communicates over the network";
    case FIRI_CAP_PROCESS:
        return L"can launch processes or inject code";
    case FIRI_CAP_DISK:
        return L"performs low-level disk operations";
    case FIRI_CAP_SERVICE:
        return L"can install or modify services";
    case FIRI_CAP_CLIPBOARD:
        return L"accesses the clipboard";
    case FIRI_CAP_MONITOR:
        return L"monitors input or installs hooks";
    default:
        return L"unknown behavior";
    }
}

static void ModuleUnload(ModuleInst& m);

static bool IsUrl(const std::wstring& s)
{
    return _wcsnicmp(s.c_str(), L"http://", 7) == 0 ||
           _wcsnicmp(s.c_str(), L"https://", 8) == 0;
}

/* ---------------- FIRI API implementation -------------------------- */

static void ApiOut(const wchar_t* fmt, ...)
{
    wchar_t buf[8192];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnwprintf(buf, 8191, fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 8191;
    buf[n] = 0;
    Out(L"%s", buf);
}

static int ApiAskYN(const wchar_t* q)
{
    return AskYN(q) ? 1 : 0;
}

static int ApiAskYNDef(const wchar_t* q)
{
    return AskYNDef(q) ? 1 : 0;
}

static const wchar_t* ApiPrompt(const wchar_t* label)
{
    g_promptBuf = PromptLine(label);
    return g_promptBuf.c_str();
}

static void ApiPause()
{
    PauseEnter();
}

static int ApiRunCapture(const wchar_t* cmdline, const wchar_t** outText,
                         unsigned long* outLen)
{
    static std::wstring last;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdline, &argc);
    if (!argv)
        return -1;
    std::vector<std::wstring> chunks;
    std::vector<std::wstring>* saved = g_capture;
    g_capture = &chunks;
    int rc = ExecCli(argc, argv);
    g_capture = saved;
    LocalFree(argv);
    last.clear();
    for (size_t i = 0; i < chunks.size(); i++)
        last += chunks[i];
    if (outText)
        *outText = last.c_str();
    if (outLen)
        *outLen = (unsigned long)last.size();
    return rc;
}

static void ApiSysInfo(FiriSysInfo* o)
{
    memset(o, 0, sizeof(*o));
    RTL_OSVERSIONINFOW vi;
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (nt)
    {
        typedef LONG(WINAPI * FN)(PRTL_OSVERSIONINFOW);
        FN f = (FN)GetProcAddress(nt, "RtlGetVersion");
        if (f)
            f(&vi);
    }
    o->osMajor = vi.dwMajorVersion;
    o->osMinor = vi.dwMinorVersion;
    o->osBuild = vi.dwBuildNumber;
    o->osRevision = (DWORD)(vi.dwBuildNumber & 0xFFFF);
    o->bootMode = BootMode();
    o->elevated = IsElevated() ? 1 : 0;
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    o->arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
                  ? FIRI_ARCH_ARM64
                  : (sizeof(void*) == 8 ? FIRI_ARCH_X64 : FIRI_ARCH_X86);
    wchar_t b[80];
    DWORD cl = 64, ul = 64;
    if (GetComputerNameW(b, &cl))
        wcsncpy(o->computer, b, 64);
    if (GetUserNameW(b, &ul))
        wcsncpy(o->user, b, 64);
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0,
                      KEY_READ, &k) == ERROR_SUCCESS)
    {
        DWORD ty = 0, sz = (DWORD)sizeof(o->cpu);
        RegQueryValueExW(k, L"ProcessorNameString", NULL, &ty, (BYTE*)o->cpu,
                         &sz);
        RegCloseKey(k);
    }
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        o->totalRamMB = ms.ullTotalPhys / (1024 * 1024);
}

static void ApiSetCursor(int show)
{
    Out(L"%s", show ? col::ShowCur : col::HideCur);
}

static void ApiClrScr()
{
    ClrScr();
}

static void ApiAddTab(const wchar_t* tab)
{
    if (!g_ctx || !tab)
        return;
    for (size_t i = 0; i < g_ctx->tabs.size(); i++)
        if (_wcsicmp(g_ctx->tabs[i].c_str(), tab) == 0)
            return;
    g_ctx->tabs.push_back(tab);
}

static void ApiAddButton(const wchar_t* tab, const wchar_t* label,
                         FiriModuleFn cb)
{
    if (!g_ctx || !label || !cb)
        return;
    for (size_t i = 0; i < g_ctx->buttons.size(); i++)
        if (g_ctx->buttons[i].cb == cb &&
            _wcsicmp(g_ctx->buttons[i].label.c_str(), label) == 0)
            return;
    ModuleButton b;
    b.tab = tab ? tab : L"";
    b.label = label;
    b.cb = cb;
    g_ctx->buttons.push_back(b);
}

static void ApiAddLabel(const wchar_t* name, const wchar_t* value)
{
    if (!g_ctx || !name)
        return;
    for (size_t i = 0; i < g_ctx->labels.size(); i++)
        if (_wcsicmp(g_ctx->labels[i].first.c_str(), name) == 0)
        {
            g_ctx->labels[i].second = value ? value : L"";
            return;
        }
    g_ctx->labels.push_back({ name, value ? value : L"" });
}

static void SetupApi()
{
    memset(&g_api, 0, sizeof(g_api));
    g_api.ver = FIRI_API_VERSION;
    g_api.Out = ApiOut;
    g_api.AskYN = ApiAskYN;
    g_api.AskYNDef = ApiAskYNDef;
    g_api.Prompt = ApiPrompt;
    g_api.Pause = ApiPause;
    g_api.RunCapture = ApiRunCapture;
    g_api.SysInfo = ApiSysInfo;
    g_api.SetCursor = ApiSetCursor;
    g_api.ClrScr = ApiClrScr;
    g_api.AddTab = ApiAddTab;
    g_api.AddButton = ApiAddButton;
    g_api.AddLabel = ApiAddLabel;
}

/* ---------------- metadata parse ----------------------------------- */

static bool ParseMeta(const std::vector<BYTE>& raw, ModuleInst& m)
{
    std::vector<BYTE> meta;
    if (!ExtractResourceData(raw, L"FIRIMETA", meta))
        return false;
    if (meta.size() < sizeof(FiriMetaBin))
        return false;
    FiriMetaBin h;
    memcpy(&h, meta.data(), sizeof(h));
    if (h.magic != FIRI_META_MAGIC)
        return false;

    const BYTE* p = meta.data() + sizeof(h);
    size_t avail = meta.size() - sizeof(h);
    if (avail < (size_t)h.idLen + h.nameLen + h.verLen + h.authorLen +
                    h.labelBytes)
        return false;

    m.id = Utf8Bytes(p, h.idLen);
    p += h.idLen;
    m.name = Utf8Bytes(p, h.nameLen);
    p += h.nameLen;
    m.version = Utf8Bytes(p, h.verLen);
    p += h.verLen;
    m.author = Utf8Bytes(p, h.authorLen);
    p += h.authorLen;

    size_t end = h.labelBytes, pos = 0;
    while (pos < end)
    {
        size_t n0 = pos;
        while (n0 < end && p[n0])
            n0++;
        if (n0 >= end)
            break;
        size_t n1 = n0 + 1;
        while (n1 < end && p[n1])
            n1++;
        std::wstring k = Utf8Bytes(p + pos, n0 - pos);
        std::wstring v = Utf8Bytes(p + n0 + 1, n1 - (n0 + 1));
        if (!k.empty())
            m.labels.push_back({ k, v });
        pos = n1 + 1;
    }

    if (m.name.empty())
        m.name = m.id;
    m.caps = h.capFlags & FIRI_CAP_ALL;
    m.flags = h.flags;
    return true;
}

static bool IsValidId(const std::wstring& id)
{
    if (id.size() < 1 || id.size() > 48)
        return false;
    for (size_t i = 0; i < id.size(); i++)
    {
        wchar_t c = id[i];
        bool ok = (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') ||
                  c == L'-' || c == L'_' || c == L'.';
        if (!ok)
            return false;
    }
    return true;
}

static ModuleInst* FindModule(const std::wstring& id)
{
    for (size_t i = 0; i < g_mods.size(); i++)
        if (_wcsicmp(g_mods[i].id.c_str(), id.c_str()) == 0)
            return &g_mods[i];
    return NULL;
}

/* ---------------- module lifecycle --------------------------------- */

static bool LoadModuleImage(ModuleInst& m, bool runEntry)
{
    if (m.builtin)
    {
        m.loaded = true;
        return true;
    }
    m.loaded = false;
    m.loadError.clear();
    if (m.raw.empty())
    {
        m.loadError = L"empty module";
        return false;
    }

    m.base = MapModuleInMemory(m.raw, m.entryPoint);
    if (!m.base)
    {
        m.loadError = L"bad or corrupt module image";
        return false;
    }
    m.entry = (FiriModuleEntryFn)LookupExport(m.base, "FiriModuleEntry");
    m.run = (FiriModuleFn)LookupExport(m.base, "FiriModuleRun");
    if (!m.entry)
    {
        m.loadError = L"module does not export FiriModuleEntry";
        ModuleUnload(m);
        return false;
    }
    if (m.entryPoint)
    {
        BOOL(WINAPI * e)(HINSTANCE, DWORD, LPVOID) =
            (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))m.entryPoint;
        e((HINSTANCE)m.base, DLL_PROCESS_ATTACH, NULL);
    }
    m.loaded = true;
    if (runEntry)
    {
        g_ctx = &m;
        int rc = m.entry(&g_api);
        g_ctx = NULL;
        if (rc != 0)
            m.loadError = L"module entry returned error";
    }
    return true;
}

static void ModuleUnload(ModuleInst& m)
{
    if (m.builtin)
        return;
    if (m.entryPoint && m.loaded)
    {
        BOOL(WINAPI * e)(HINSTANCE, DWORD, LPVOID) =
            (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))m.entryPoint;
        e((HINSTANCE)m.base, DLL_PROCESS_DETACH, NULL);
    }
    if (m.base)
        VirtualFree(m.base, 0, MEM_RELEASE);
    m.base = NULL;
    m.entryPoint = NULL;
    m.entry = NULL;
    m.run = NULL;
    m.buttons.clear();
    m.loaded = false;
}

/* ---------------- module add / remove ------------------------------ */

bool AddModuleFile(const std::wstring& path)
{
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        LastErr(L"open module file");
        return false;
    }
    DWORD hi = 0, sz = GetFileSize(f, &hi);
    if (hi || sz == 0 || sz > (1u << 26))
    {
        CloseHandle(f);
        Out(L"%s[!]%s module is too large or empty\n", col::Red, col::R);
        return false;
    }
    std::vector<BYTE> raw(sz);
    DWORD got = 0, done = 0;
    while (done < sz)
    {
        if (!ReadFile(f, raw.data() + done, sz - done, &got, NULL) || !got)
            break;
        done += got;
    }
    CloseHandle(f);

    ModuleInst m{};
    if (!ParseMeta(raw, m))
    {
        Out(L"%s[!]%s not a valid FIRI module (missing FIRIMETA resource)\n",
            col::Red, col::R);
        Out(L"    rebuild it with the firi-module-template.\n");
        return false;
    }
    if (!IsValidId(m.id))
    {
        Out(L"%s[!]%s invalid module id '%s'\n", col::Red, col::R,
            m.id.c_str());
        return false;
    }
    if (FindModule(m.id))
    {
        Out(L"%s[!]%s module '%s' is already present\n", col::Red, col::R,
            m.id.c_str());
        return false;
    }

    m.capsDetected = ScanImports(raw);
    m.raw = raw;

    Out(L"%smodule:%s %s v%s\n", col::Cyn, col::R, m.name.c_str(),
        m.version.c_str());
    Out(L"  id      : %s\n", m.id.c_str());
    Out(L"  author  : %s\n", m.author.empty() ? L"(unknown)" : m.author.c_str());
    Out(L"  caps    : declared [%s]  detected [%s]\n",
        CapsList(m.caps).c_str(), CapsList(m.capsDetected).c_str());

    DWORD danger = m.caps | m.capsDetected;
    if (danger && !IsDevMode())
    {
        Out(L"\n%s[warn]%s this module:\n", col::Yel, col::R);
        for (DWORD bit = FIRI_CAP_REGISTRY; bit <= FIRI_CAP_MONITOR; bit <<= 1)
            if (danger & bit)
                Out(L"  %s- %s%s\n", col::Yel, CapWarning(bit), col::R);
        if (!AskYN(L"add this module anyway? (it may touch your system)"))
        {
            Out(L"cancelled. module not added.\n");
            return false;
        }
    }

    if (!SelfWriteResource((L"FIRIMOD-" + m.id).c_str(), raw.data(),
                           (DWORD)raw.size()))
    {
        LastErr(L"embedding module");
        return false;
    }
    LoadModuleImage(m, true);
    g_mods.push_back(m);
    Out(L"%s[+]%s module '%s' embedded into firiu.exe and loaded\n",
        col::Grn, col::R, m.name.c_str());
    if (!m.loaded)
        Out(L"%s[!]%s not active: %s\n", col::Red, col::R,
            m.loadError.c_str());
    return true;
}

bool RemoveModule(const std::wstring& id)
{
    ModuleInst* m = FindModule(id);
    if (!m)
    {
        Out(L"[!] module '%s' not found\n", id.c_str());
        return false;
    }
    const wchar_t* criticalMsg =
        L"Module is critical for the work of FIRI Unlocker. It cannot be "
        L"removed without developer mode.";
    if ((m->flags & FIRI_META_FLAG_CRITICAL) && !IsDevMode())
    {
        Out(L"%serror -3:%s %s\n", col::Red, col::R, criticalMsg);
        return false;
    }
    if (m->builtin)
    {
        if (!IsDevMode())
            Out(L"%serror -3:%s %s\n", col::Red, col::R, criticalMsg);
        else
            Out(L"%s[!]%s firiu.core is the host program itself and cannot "
                L"be removed, even in developer mode.\n",
                col::Red, col::R);
        return false;
    }

    size_t idx = (size_t)(m - &g_mods[0]);
    ModuleUnload(*m);
    if (!SelfDeleteResource((L"FIRIMOD-" + id).c_str()))
    {
        LastErr(L"removing module resource");
        return false;
    }
    g_mods.erase(g_mods.begin() + idx);
    Out(L"%s[+]%s module '%s' removed\n", col::Grn, col::R, id.c_str());
    return true;
}

void CmdModuleAdd(const std::wstring& path)
{
    AddModuleFile(path);
}

void CmdModuleRemove(const std::wstring& id)
{
    RemoveModule(id);
}

/* ---------------- built-in core module ----------------------------- */

static void AddBuiltin()
{
    ModuleInst core{};
    core.id = L"firiu.core";
    core.name = L"FIRI Unlocker functionality";
    core.version = kVersion;
    core.author = L"FIRI Project";
    core.labels.push_back(
        { L"GitHub Link", L"https://github.com/fixitrecoverit/" });
    core.caps = FIRI_CAP_ALL;
    core.capsDetected = FIRI_CAP_ALL;
    core.flags = FIRI_META_FLAG_CRITICAL;
    core.builtin = true;
    core.loaded = true;
    g_mods.push_back(core);
}

/* ---------------- module view -------------------------------------- */

static const wchar_t* kModuleKeys =
    L"123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void PrintModulePanel(const ModuleInst& m)
{
    Out(L"%sname%s   : %s v%s\n", col::Wht, col::R, m.name.c_str(),
        m.version.c_str());
    Out(L"%sid%s     : %s\n", col::Wht, col::R, m.id.c_str());
    Out(L"%sauthor%s : %s\n", col::Wht, col::R,
        m.author.empty() ? L"(unknown)" : m.author.c_str());
    Out(L"%sstatus%s : %s\n", col::Wht, col::R,
        m.loaded ? L"active" : L"not loaded");
    if (!m.loaded && !m.loadError.empty())
        Out(L"%s        : %s%s\n", col::Yel, m.loadError.c_str(), col::R);
    Out(L"%scaps%s   : declared [%s]\n", col::Wht, col::R,
        CapsList(m.caps).c_str());
    if (!m.builtin)
        Out(L"           detected [%s]\n", CapsList(m.capsDetected).c_str());
    if (m.flags & FIRI_META_FLAG_CRITICAL)
        Out(L"           %s[critical - cannot be removed without "
            L"devmode]%s\n", col::Red, col::R);
    for (size_t i = 0; i < m.labels.size(); i++)
    {
        Out(L"%s%-10s : ", col::Wht, m.labels[i].first.c_str());
        if (IsUrl(m.labels[i].second))
            Out(L"%s%s%s\n", col::Link, m.labels[i].second.c_str(), col::R);
        else
            Out(L"%s\n", m.labels[i].second.c_str());
    }
    if (!m.buttons.empty())
    {
        Out(L"%sbuttons%s : ", col::Wht, col::R);
        std::wstring a;
        for (size_t i = 0; i < m.buttons.size(); i++)
        {
            if (!a.empty())
                a += L", ";
            if (!m.buttons[i].tab.empty())
                a += L"[" + m.buttons[i].tab + L"] ";
            a += m.buttons[i].label;
        }
        Out(L"%s\n", a.c_str());
    }
}

static void ViewModule(ModuleInst& m)
{
    for (;;)
    {
        ClrScr();
        PrintModulePanel(m);
        Out(L"\n");

        struct Row
        {
            wchar_t key;
            std::wstring label;
            int kind; /* 1 button, 2 url, 3 remove, 4 note */
            int arg;
        };
        std::vector<Row> rows;
        std::vector<std::wstring> urlValues;
        wchar_t* kc = (wchar_t*)kModuleKeys;
        int nextKey = 0;

        for (size_t i = 0; i < m.buttons.size(); i++)
        {
            Row r;
            r.key = kc[nextKey++];
            r.kind = 1;
            r.arg = (int)i;
            r.label = m.buttons[i].tab.empty()
                          ? m.buttons[i].label
                          : L"[" + m.buttons[i].tab + L"] " +
                                m.buttons[i].label;
            rows.push_back(r);
        }
        if (m.builtin)
        {
            Row r;
            r.key = kc[nextKey++];
            r.kind = 4; /* note, no-op */
            r.arg = 0;
            r.label = L"core module - use the main menu for its features";
            rows.push_back(r);
        }
        {
            Row r;
            r.key = L'r';
            r.kind = 3;
            r.arg = 0;
            r.label = L"remove module";
            rows.push_back(r);
        }
        for (size_t i = 0; i < m.labels.size(); i++)
        {
            if (!IsUrl(m.labels[i].second))
                continue;
            Row r;
            r.key = kc[nextKey++];
            r.kind = 2;
            r.arg = (int)urlValues.size();
            urlValues.push_back(m.labels[i].second);
            r.label = urlValues.back();
            rows.push_back(r);
        }
        {
            Row r;
            r.key = L'0';
            r.kind = 0;
            r.arg = 0;
            r.label = L"back";
            rows.push_back(r);
        }

        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        bool interactive = StdinIsConsole();
        int sel = 0;
        DWORD oldMode = 0;
        COORD origin;
        CONSOLE_SCREEN_BUFFER_INFO bi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &bi);
        origin = bi.dwCursorPosition;

        if (!interactive)
        {
            std::wstring c = Trim(PromptLine(L"choice> "));
            if (c.empty())
                return;
            for (size_t i = 0; i < rows.size(); i++)
                if (rows[i].key == c[0])
                    sel = (int)i;
            goto act;
        }

        GetConsoleMode(hIn, &oldMode);
        SetConsoleMode(hIn, (g_cfg.mouse ? ENABLE_MOUSE_INPUT : 0) |
                               ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS |
                               ENABLE_PROCESSED_INPUT);
        Out(L"%s", col::HideCur);
        for (;;)
        {
            for (size_t i = 0; i < rows.size(); i++)
            {
                bool hover = (int)i == sel;
                Out(L" %s%s%s %s[%c]%s %s\n", hover ? col::Sel : L"",
                    hover ? L">" : L" ", hover ? col::R : L"", col::Wht,
                    rows[i].key, col::R, rows[i].label.c_str());
            }
            Out(L"\n%sarrows/click/enter ok, esc/0 back%s\n", col::Dim,
                col::R);

            INPUT_RECORD rec[16];
            DWORD n = 0;
            if (!ReadConsoleInputW(hIn, rec, 16, &n) || n == 0)
                break;
            for (DWORD k2 = 0; k2 < n; k2++)
            {
                if (rec[k2].EventType == KEY_EVENT &&
                    rec[k2].Event.KeyEvent.bKeyDown)
                {
                    WORD vk = rec[k2].Event.KeyEvent.wVirtualKeyCode;
                    wchar_t ch = rec[k2].Event.KeyEvent.uChar.AsciiChar;
                    if (vk == VK_UP)
                        sel = (sel - 1 + (int)rows.size()) % rows.size();
                    else if (vk == VK_DOWN || vk == VK_TAB)
                        sel = (sel + 1) % rows.size();
                    else if (vk == VK_RETURN)
                        goto act;
                    else if (vk == VK_ESCAPE)
                    {
                        sel = (int)rows.size() - 1;
                        goto act;
                    }
                    else if (ch == L'0')
                    {
                        sel = (int)rows.size() - 1;
                        goto act;
                    }
                    else
                    {
                        for (size_t i = 0; i < rows.size(); i++)
                            if (rows[i].key == ch)
                            {
                                sel = (int)i;
                                goto act;
                            }
                    }
                }
                else if (rec[k2].EventType == MOUSE_EVENT)
                {
                    MOUSE_EVENT_RECORD& me = rec[k2].Event.MouseEvent;
                    int row = me.dwMousePosition.Y - origin.Y;
                    if (row >= 0 && row < (int)rows.size())
                    {
                        if (me.dwEventFlags == MOUSE_MOVED)
                            sel = row;
                        else if ((me.dwButtonState &
                                  FROM_LEFT_1ST_BUTTON_PRESSED) &&
                                 me.dwEventFlags != MOUSE_WHEELED &&
                                 me.dwEventFlags != MOUSE_HWHEELED)
                        {
                            sel = row;
                            goto act;
                        }
                    }
                }
            }
            ClrScr();
            PrintModulePanel(m);
            Out(L"\n");
            GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &bi);
            origin = bi.dwCursorPosition;
        }
        break;

    act:
        if (interactive)
            SetConsoleMode(hIn, oldMode);
        Out(L"%s", col::ShowCur);
        Out(L"\n");
        if (sel < 0 || sel >= (int)rows.size())
            return;
        Row& picked = rows[sel];
        if (picked.kind == 0)
            return;
        if (picked.kind == 1)
        {
            ModuleButton& b = m.buttons[picked.arg];
            g_ctx = &m;
            b.cb(&g_api);
            g_ctx = NULL;
            PauseEnter();
            continue;
        }
        if (picked.kind == 2)
        {
            if (picked.arg < (int)urlValues.size())
                OpenUrl(urlValues[picked.arg]);
            continue;
        }
        if (picked.kind == 4)
            continue;
        if (picked.kind == 3)
        {
            ModuleUnload(m);
            if (RemoveModule(m.id))
                return;
            continue;
        }
    }
}

/* ---------------- modules menu ------------------------------------- */

void CmdModules()
{
    for (;;)
    {
        std::vector<std::wstring> labels;
        std::vector<MenuItem> items;

        size_t shown = (std::min)(g_mods.size(), (size_t)34);
        labels.reserve(shown + 2);
        labels.push_back(L"add module from .firiumodule file");
        for (size_t i = 0; i < shown; i++)
        {
            const ModuleInst& m = g_mods[i];
            labels.push_back(m.name + L" v" + m.version +
                             (m.builtin ? L"  [builtin]"
                                        : (!m.loaded ? L"  [broken]"
                                                     : L"")));
        }
        labels.push_back(L"back");

        items.reserve(labels.size());
        items.push_back({ L'a', labels[0].c_str() });
        for (size_t i = 0; i < shown; i++)
        {
            wchar_t key = (i < 9) ? (wchar_t)(L'1' + i)
                                  : (wchar_t)(L'b' + (i - 9));
            items.push_back({ key, labels[i + 1].c_str() });
        }
        items.push_back({ L'0', labels[labels.size() - 1].c_str() });

        int pick = RunMenu(L"modules", items.data(), (int)items.size());
        if (pick < 0 || items[pick].key == L'0')
            return;
        if (items[pick].key == L'a')
        {
            std::wstring p = PromptLine(L"path to .firiumodule> ");
            if (!p.empty())
            {
                ClrScr();
                AddModuleFile(p);
                PauseEnter();
            }
            continue;
        }
        size_t mi;
        if (items[pick].key >= L'b' && items[pick].key <= L'z')
            mi = 9 + (size_t)(items[pick].key - L'b');
        else
            mi = (size_t)(items[pick].key - L'1');
        if (mi < g_mods.size())
            ViewModule(g_mods[mi]);
    }
}

void InitModules()
{
    SetupApi();
    AddBuiltin();

    struct EnumNames
    {
        static BOOL CALLBACK Cb(HMODULE h, LPCWSTR t, LPWSTR n, LONG_PTR l)
        {
            (void)h;
            (void)t;
            std::vector<std::wstring>& out =
                *(std::vector<std::wstring>*)l;
            if (IS_INTRESOURCE(n))
                return TRUE;
            if (wcsncmp(n, L"FIRIMOD-", 8) == 0)
                out.push_back(n);
            return TRUE;
        }
    };

    std::vector<std::wstring> names;
    EnumResourceNamesW(NULL, RT_RCDATA, EnumNames::Cb, (LONG_PTR)&names);
    std::sort(names.begin(), names.end());

    for (size_t i = 0; i < names.size(); i++)
    {
        ModuleInst m{};
        m.id = names[i].substr(8);
        std::vector<BYTE> raw;
        if (!SelfReadResource(names[i].c_str(), raw))
            continue;
        m.raw = raw;
        if (!ParseMeta(raw, m))
        {
            m.loaded = false;
            m.loadError = L"bad FIRIMETA in embedded module";
            if (m.name.empty())
                m.name = m.id;
            g_mods.push_back(m);
            continue;
        }
        m.capsDetected = ScanImports(raw);
        LoadModuleImage(m, true);
        g_mods.push_back(m);
    }
}

/* ---------------- developer mode ----------------------------------- */

bool IsDevMode()
{
    return g_cfg.devmode;
}

void CmdDevMode()
{
    for (;;)
    {
        Out(L"\n%sdeveloper mode is %s%s%s%s\n", col::Wht, col::R,
            IsDevMode() ? col::Grn : col::Dim,
            IsDevMode() ? L"ENABLED" : L"DISABLED", col::R);
        Out(L"\n");
        MenuItem items[] = {
            { L'e', L"enable developer mode", IsDevMode() },
            { L'd', L"disable developer mode", !IsDevMode() },
            { L'0', L"back", false },
        };
        int pick = RunMenu(L"developer mode", items, 3);
        if (pick < 0 || items[pick].key == L'0')
            return;

        if (items[pick].key == L'e')
        {
            std::wstring q =
                std::wstring(L"Are you sure? This removes ") + col::Red +
                L"ALL" + col::R + L" restrictions. (yes/no)";
            if (!AskYN(q.c_str()))
            {
                Out(L"cancelled. developer mode stays %sOFF%s.\n", col::Dim,
                    col::R);
                continue;
            }
            q = std::wstring(L"Are you TOTALLY sure? This removes ") +
                col::Red + L"ALL" + col::R + L" restrictions " + col::RedB +
                L"AT ALL" + col::R +
                L". There would be no defense against removal of "
                L"functionality or other restrictions. (yes/no)";
            if (!AskYN(q.c_str()))
            {
                Out(L"cancelled. developer mode stays %sOFF%s.\n", col::Dim,
                    col::R);
                continue;
            }
            q = std::wstring(L"Are you REALLY TOTALLY sure? You will be able "
                             L"to ") +
                col::Red + L"remove critical modules" + col::R + L", " +
                col::Red + L"remove functionality" + col::R +
                L", access other restricted features and more. (yes/no)";
            if (!AskYN(q.c_str()))
            {
                Out(L"cancelled. developer mode stays %sOFF%s.\n", col::Dim,
                    col::R);
                continue;
            }
            g_cfg.devmode = true;
            SaveCfg();
            Out(L"\n%sDeveloper Mode enabled! Have fun! You can always "
                L"disable it in settings.%s\n",
                col::Grn, col::R);
            PauseEnter();
            continue;
        }
        if (items[pick].key == L'd')
        {
            if (!AskYN(L"Are you sure you want to disable Developer Mode? "
                       L"All restrictions come back."))
            {
                Out(L"cancelled. developer mode stays %sON%s.\n", col::Dim,
                    col::R);
                continue;
            }
            g_cfg.devmode = false;
            SaveCfg();
            Out(L"\n%sDeveloper Mode disabled. Restrictions are active "
                L"again.%s\n", col::Grn, col::R);
            PauseEnter();
            continue;
        }
    }
}

/* ---------------- public accessors --------------------------------- */