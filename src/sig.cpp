#include "sig.h"
#include "common.h"
#include <softpub.h>
#include <mscat.h>
#include <map>

static bool IsCatalogSigned(const std::wstring& file)
{
    HCATADMIN ha = NULL;
    GUID action = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&ha, &action, 0))
        return false;

    bool found = false;
    HANDLE f = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE)
    {
        DWORD hs = 0;
        if (CryptCATAdminCalcHashFromFileHandle(f, &hs, NULL, 0) && hs)
        {
            std::vector<BYTE> hash(hs);
            if (CryptCATAdminCalcHashFromFileHandle(f, &hs, hash.data(), 0))
            {
                HCATINFO ci =
                    CryptCATAdminEnumCatalogFromHash(ha, hash.data(), hs, 0,
                                                     NULL);
                while (ci)
                {
                    HCATINFO next = CryptCATAdminEnumCatalogFromHash(
                        ha, hash.data(), hs, 0, &ci);
                    CryptCATAdminReleaseCatalogContext(ha, ci, 0);
                    ci = next;
                    found = true;
                }
            }
        }
        CloseHandle(f);
    }
    CryptCATAdminReleaseContext(ha, 0);
    return found;
}

static int VerifyOnce(const std::wstring& file)
{
    WINTRUST_FILE_INFO fi;
    memset(&fi, 0, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = file.c_str();

    WINTRUST_DATA wd;
    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.dwStateAction = WTD_STATEACTION_IGNORE;
    wd.pFile = &fi;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

    if (r == ERROR_SUCCESS)
        return 1;
    if (r == (LONG)TRUST_E_NOSIGNATURE)
        return IsCatalogSigned(Lower(file)) ? 1 : 0;
    return -1;
}

int VerifyFileSig(const std::wstring& file)
{
    static std::map<std::wstring, int> cache;
    std::wstring key = Lower(file);
    std::map<std::wstring, int>::iterator it = cache.find(key);
    if (it != cache.end())
        return it->second;

    int res = -1;
    DWORD attr = GetFileAttributesW(file.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
        res = VerifyOnce(Lower(file));
    cache[key] = res;
    return res;
}

static bool ExtractExePath(const std::wstring& raw, std::wstring& out)
{
    std::wstring v = raw;
    if (v.find(L'%') != std::wstring::npos)
    {
        wchar_t buf[2048];
        if (ExpandEnvironmentStringsW(v.c_str(), buf, 2048))
            v = buf;
    }

    size_t p = v.find(L'"');
    if (p != std::wstring::npos)
    {
        size_t e = v.find(L'"', p + 1);
        if (e != std::wstring::npos)
        {
            std::wstring cand = Trim(v.substr(p + 1, e - p - 1));
            if (!cand.empty() &&
                (Lower(cand).find(L".exe") != std::wstring::npos ||
                 Lower(cand).find(L".dll") != std::wstring::npos ||
                 Lower(cand).find(L".sys") != std::wstring::npos))
            {
                out = cand;
                return true;
            }
        }
    }

    std::wstring low = Lower(v);
    size_t x = low.find(L".exe");
    if (x == std::wstring::npos)
        x = low.find(L".dll");
    if (x == std::wstring::npos)
        x = low.find(L".sys");
    if (x == std::wstring::npos)
        return false;

    size_t s = 0;
    for (size_t i = 0; i < x + 4; i++)
        if (v[i] == L' ' || v[i] == L'\t')
            s = i + 1;
    out = Trim(v.substr(s, x + 4 - s));
    return !out.empty();
}

const wchar_t* SigTagForCommand(const std::wstring& cmdlineRaw)
{
    std::wstring path;
    if (!ExtractExePath(cmdlineRaw, path))
        return NULL;

    if (path.size() < 2 || path[1] != L':')
    {
        std::wstring base = SysDir() + L"\\" + path;
        if (GetFileAttributesW(base.c_str()) != INVALID_FILE_ATTRIBUTES)
            path = base;
        else
        {
            base = WinDir() + L"\\" + path;
            if (GetFileAttributesW(base.c_str()) == INVALID_FILE_ATTRIBUTES)
                return NULL;
            path = base;
        }
    }

    switch (VerifyFileSig(path))
    {
    case 1:  return L"[signed]";
    case 0:  return L"[UNSIGNED]";
    default:
    {
        DWORD a = GetFileAttributesW(path.c_str());
        if (a == INVALID_FILE_ATTRIBUTES)
            return L"[missing]";
        return L"[BAD-SIG]";
    }
    }
}
