#include "cert.h"
#include <wincrypt.h>
#include <wintrust.h>

namespace
{

std::wstring DisplayName(const CERT_CONTEXT* c)
{
    wchar_t name[256] = L"";
    if (CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name,
                           256) > 1)
        return name;
    return std::wstring();
}

/* Pull the PKCS#7 Authenticode blob out of this executable's own PE security
 * directory.  Empty when the binary is not signed. */
std::vector<BYTE> SelfSignature()
{
    std::vector<BYTE> out;

    std::wstring path = SelfPath();
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return out;
    DWORD sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 0x200 || sz > (256 << 20))
    {
        CloseHandle(f);
        return out;
    }

    std::vector<BYTE> data(sz);
    DWORD got = 0;
    ReadFile(f, data.data(), sz, &got, NULL);
    CloseHandle(f);
    if (got < 0x200)
        return out;
    data.resize(got);

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > data.size())
        return out;

    const IMAGE_NT_HEADERS* nt =
        (const IMAGE_NT_HEADERS*)(data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY)
        return out;

    const IMAGE_DATA_DIRECTORY& sec =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (!sec.VirtualAddress || sec.Size < sizeof(WIN_CERTIFICATE) ||
        (size_t)sec.VirtualAddress + sec.Size > data.size())
        return out;

    const WIN_CERTIFICATE* wc =
        (const WIN_CERTIFICATE*)(data.data() + sec.VirtualAddress);
    if (wc->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA ||
        wc->dwLength < sizeof(WIN_CERTIFICATE) ||
        (size_t)sec.VirtualAddress + wc->dwLength > data.size())
        return out;

    size_t hdr = FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
    size_t n = wc->dwLength - hdr;
    const BYTE* pk = (const BYTE*)wc + hdr;
    out.assign(pk, pk + n);
    return out;
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
        if (_wcsicmp(DisplayName(c).c_str(), subject.c_str()) == 0)
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
    std::vector<BYTE> pkcs7 = SelfSignature();
    if (pkcs7.empty())
        return;

    CRYPT_DATA_BLOB blob = {(DWORD)pkcs7.size(), pkcs7.data()};
    HCERTSTORE sig = NULL;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL,
                          &sig, NULL, NULL) ||
        !sig)
        return;

    const CERT_CONTEXT* leaf = NULL;
    const CERT_CONTEXT* root = NULL;
    const CERT_CONTEXT* c = NULL;
    while ((c = CertEnumCertificatesInStore(sig, c)) != NULL)
    {
        if (!leaf)
            leaf = c;
        root = c;
    }
    leaf = leaf ? CertDuplicateCertificateContext(leaf) : NULL;
    root = root ? CertDuplicateCertificateContext(root) : NULL;
    CertCloseStore(sig, CERT_CLOSE_STORE_FORCE_FLAG);

    if (!leaf)
    {
        if (root)
            CertFreeCertificateContext(root);
        return;
    }

    std::wstring subject = DisplayName(leaf);
    if (subject.empty())
    {
        CertFreeCertificateContext(leaf);
        CertFreeCertificateContext(root);
        return;
    }

    if (!StoreHasSubject(L"TrustedPublisher", subject))
    {
        Out(L"%sWould you like to install the FIRI Project Code Signing "
            L"Certificate?%s\n",
            col::Cyn, col::R);
        Out(L"This will make Windows trust all FIRI tools more and will "
            L"remove the SmartScreen (most of the time).\n");
        if (AskYNDef(L"install the certificate (TrustedPublisher and ROOT)?"))
        {
            bool any = false;
            any |= AddToStore(L"TrustedPublisher", leaf);
            if (root)
                any |= AddToStore(L"ROOT", root);
            if (any)
                Out(L"%s[+]%s '%s' installed into local machine trust\n",
                    col::Grn, col::R, subject.c_str());
            else
                Out(L"%s[!]%s install failed (%lu)\n", col::Red, col::R,
                    (unsigned long)GetLastError());
        }
    }

    CertFreeCertificateContext(leaf);
    CertFreeCertificateContext(root);
}