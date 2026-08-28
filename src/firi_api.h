/*
 * firi_api.h -- FIRI Unlocker module API (ABI contract).
 *
 * This header is shared between FIRI Unlocker itself (src/firi_api.h) and
 * third-party modules built from the firi-module-template repository.  It
 * must stay binary-compatible; bump FIRI_API_VERSION and add fields at the
 * end when extending.
 *
 * A module is a small PE (DLL) image compiled against this header, delivered
 * as a .firiumodule file.  It carries a "FIRIMETA" RT_RCDATA resource with a
 * FiriMetaBin descriptor (written by genmeta from the template repo).  FIRI
 * embeds the whole module inside FIRI Unlocker as a "FIRIMOD-<id>" resource
 * and executes it in-memory with a tiny PE mapper -- no extra files, no
 * registry, works in Safe Mode / WinPE / WinRE.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define FIRI_API_VERSION 1u

/* FiriMetaBin on-disk descriptor.  Header is followed by raw UTF-8 blobs:
 *   id (idLen), name (nameLen), version (verLen), author (authorLen),
 *   then labelBytes bytes of (label null-termed, value null-termed) pairs.  */
#define FIRI_META_MAGIC 0x444D4946u /* 'FIMD' */

#pragma pack(push, 1)
typedef struct FiriMetaBin
{
    unsigned long magic;      /* FIRI_META_MAGIC */
    unsigned long ver;        /* 1 */
    unsigned long idLen;
    unsigned long nameLen;
    unsigned long verLen;
    unsigned long authorLen;
    unsigned long labelBytes;
    unsigned long capFlags;   /* declared FIRI_CAP_* bitset */
    unsigned long flags;      /* FIRI_META_FLAG_* */
} FiriMetaBin;
#pragma pack(pop)

/* Module capability bits (declared by the author in meta and/or detected
 * by FIRI scanning the import table when the module is added). */
#define FIRI_CAP_REGISTRY  0x00000001u /* reads/writes the Windows registry   */
#define FIRI_CAP_FILE      0x00000002u /* creates, overwrites or deletes files */
#define FIRI_CAP_NETWORK   0x00000004u /* network / internet access           */
#define FIRI_CAP_PROCESS   0x00000008u /* launches processes or injects code   */
#define FIRI_CAP_DISK      0x00000010u /* low-level disk/volume access        */
#define FIRI_CAP_SERVICE   0x00000020u /* installs/modifies services          */
#define FIRI_CAP_CLIPBOARD 0x00000040u /* monitors or alters the clipboard    */
#define FIRI_CAP_MONITOR   0x00000080u /* hooks/hotkeys, input monitoring     */
#define FIRI_CAP_ALL       0x000000FFu

#define FIRI_META_FLAG_CRITICAL 0x00000001u /* unremovable without devmode */

/* arch values returned by FiriSysInfo.arch */
#define FIRI_ARCH_X86   0
#define FIRI_ARCH_X64   1
#define FIRI_ARCH_ARM64 2

/* bootMode values */
#define FIRI_BOOT_NORMAL 0
#define FIRI_BOOT_SAFE   1
#define FIRI_BOOT_WINPE  2

typedef struct FiriSysInfo
{
    unsigned long       osMajor;
    unsigned long       osMinor;
    unsigned long       osBuild;
    unsigned long       osRevision;
    int                 bootMode;
    int                 elevated;
    int                 arch;
    wchar_t             computer[65];
    wchar_t             user[65];
    wchar_t             cpu[193];
    unsigned long long  totalRamMB;
} FiriSysInfo;

typedef struct FiriApi FiriApi;

/* Button callback: runs inside the module's mapped image. */
typedef int (__cdecl *FiriModuleFn)(const FiriApi* api);

/*
 * FiriApi.  Layout is fixed; do not reorder.  Registration functions
 * (AddTab/AddButton/AddLabel) are meaningful while FiriModuleEntry runs.
 */
struct FiriApi
{
    unsigned long ver; /* FIRI_API_VERSION */

    void (*Out)(const wchar_t* fmt, ...);
    int (*AskYN)(const wchar_t* question);        /* default no  */
    int (*AskYNDef)(const wchar_t* question);     /* default yes */
    const wchar_t* (*Prompt)(const wchar_t* label);
    void (*Pause)(void);

    /* Run any built-in FIRI command ("info", "ps", ...) and capture its
     * output.  *outText is owned by FIRI and valid only until the next
     * RunCapture call.  Returns 0 on success. */
    int (*RunCapture)(const wchar_t* cmdline, const wchar_t** outText,
                      unsigned long* outLen);

    void (*SysInfo)(FiriSysInfo* out);

    void (*SetCursor)(int show);
    void (*ClrScr)(void);

    void (*AddTab)(const wchar_t* tab);
    void (*AddButton)(const wchar_t* tab, const wchar_t* label, FiriModuleFn cb);
    void (*AddLabel)(const wchar_t* name, const wchar_t* value);
};

/* Symbols a module may export:
 *   FiriModuleEntry(api)  -- called once at load time; register tabs/buttons
 *                            and do one-time setup.
 *   FiriModuleRun(api)    -- optional; invoked when the user picks "run"
 *                            on the module in the FIRI Modules menu.
 * int return: 0 = success, anything else = error (shown to the user). */
typedef int (__cdecl *FiriModuleEntryFn)(const FiriApi* api);

#ifdef __cplusplus
}
#endif