#include "cert.h"
#include <wincrypt.h>

namespace
{

const wchar_t* const kPassword = L"firisigning2026";

std::wstring FindPfx()
{
    std::wstring self = SelfPath();
    size_t slash = self.find_last_of(L"\\/");
    std::wstring dir =
        slash == std::wstring::npos ? std::wstring(L".") : self.substr(0, slash);
    const wchar_t* candidates[] = {L"FIRI_Project.pfx"};
    std::wstring tries[3] = {
        dir + L"\\" + candidates[0],
        dir + L"\\.." + L"\\" + candidates[0],
        candidates[0],
    };
    for (int i = 0; i < 3; i++)
        if (GetFileAttributesW(tries[i].c_str()) != INVALID_FILE_ATTRIBUTES)
            return tries[i];
    return std::wstring();
}

HCERTSTORE OpenPfx(const std::wstring& path, std::wstring& subject)
{
    subject.clear();

    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return NULL;
    DWORD sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > (1 << 20))
    {
        CloseHandle(f);
        return NULL;
    }
    std::vector<BYTE> blob(sz);
    DWORD got = 0;
    ReadFile(f, blob.data(), sz, &got, NULL);
    CloseHandle(f);

    CRYPT_DATA_BLOB pfx;
    pfx.cbData = got;
    pfx.pbData = blob.data();

    HCERTSTORE hs = PFXImportCertStore(&pfx, kPassword, CRYPT_EXPORTABLE);
    if (!hs)
        return NULL;

    const CERT_CONTEXT* c = CertEnumCertificatesInStore(hs, NULL);
    if (!c)
    {
        CertCloseStore(hs, CERT_CLOSE_STORE_FORCE_FLAG);
        return NULL;
    }
    wchar_t name[256];
    if (CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name,
                           256) > 1)
        subject = name;
    return hs;
}

bool StoreHasSubject(const wchar_t* storeName, const std::wstring& subject)
{
    HCERTSTORE st = CertOpenStore(
        (LPCSTR)CERT_STORE_PROV_SYSTEM_W,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, (const void*)storeName);
    if (!st)
        return false;

    bool found = false;
    const CERT_CONTEXT* c = NULL;
    while ((c = CertEnumCertificatesInStore(st, c)) != NULL && !found)
    {
        wchar_t name[256];
        if (CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                               name, 256) > 1 &&
            _wcsicmp(name, subject.c_str()) == 0)
            found = true;
    }
    if (c)
        CertFreeCertificateContext(c);
    CertCloseStore(st, 0);
    return found;
}

bool AddToStore(const wchar_t* storeName, const CERT_CONTEXT* ctx)
{
    HCERTSTORE st = CertOpenStore(
        (LPCSTR)CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
        (const void*)storeName);
    if (!st)
        return false;
    BOOL ok = CertAddCertificateContextToStore(st, ctx,
                                               CERT_STORE_ADD_REPLACE_EXISTING,
                                               NULL);
    CertCloseStore(st, 0);
    return ok != FALSE;
}

} 

void StartupCertCheck()
{
    std::wstring pfx = FindPfx();
    if (pfx.empty())
        return;

    std::wstring subject;
    HCERTSTORE mem = OpenPfx(pfx, subject);
    if (!mem || subject.empty())
    {
        if (mem)
            CertCloseStore(mem, CERT_CLOSE_STORE_FORCE_FLAG);
        Out(L"%s[!] could not read FIRI_Project.pfx%s\n", col::Yel, col::R);
        return;
    }

    const CERT_CONTEXT* cert = CertEnumCertificatesInStore(mem, NULL);

    bool installed = StoreHasSubject(L"TrustedPublisher", subject);
    if (!installed)
    {
        Out(L"%sWould you like to install FIRI Project certificate?%s\n",
            col::Cyn, col::R);
        Out(L"This will remove the smartscreen warning and will make "
            L"Windows trust FIRI Unlocker.\n");
        if (!AskYNDef(L"install?"))
        {
            CertCloseStore(mem, CERT_CLOSE_STORE_FORCE_FLAG);
            return;
        }

        bool any = false;
        if (cert)
        {
            any |= AddToStore(L"TrustedPublisher", cert);
            any |= AddToStore(L"ROOT", cert);
        }
        if (any)
            Out(L"%s[+]%s '%s' installed into local machine trust\n",
                col::Grn, col::R, subject.c_str());
        else
            Out(L"%s[!]%s install failed (%lu)\n", col::Red, col::R,
                (unsigned long)GetLastError());
    }

    if (cert)
        CertFreeCertificateContext(cert);
    CertCloseStore(mem, CERT_CLOSE_STORE_FORCE_FLAG);
}
