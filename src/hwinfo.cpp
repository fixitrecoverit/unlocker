#include "hwinfo.h"
#include <winioctl.h>
#include <cfgmgr32.h>

namespace
{

const DWORD kProbNotPresent = 24;
const DWORD kProbNoDriver = 28;

std::wstring RegGetString(HKEY root, const std::wstring& key, const wchar_t* value)
{
    std::wstring out;
    HKEY k;
    if (RegOpenKeyExW(root, key.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS)
        return out;
    DWORD ty = 0, sz = 0;
    if (RegQueryValueExW(k, value, NULL, &ty, NULL, &sz) == ERROR_SUCCESS &&
        (ty == REG_SZ || ty == REG_EXPAND_SZ) && sz >= sizeof(wchar_t))
    {
        std::vector<BYTE> buf(sz + sizeof(wchar_t), 0);
        DWORD got = sz;
        if (RegQueryValueExW(k, value, NULL, &ty, buf.data(), &got) == ERROR_SUCCESS)
        {
            out.assign((const wchar_t*)buf.data());
            size_t z = out.find(L'\0');
            if (z != std::wstring::npos)
                out.resize(z);
        }
    }
    RegCloseKey(k);
    return out;
}

std::string OffsetString(const STORAGE_DEVICE_DESCRIPTOR* d, DWORD off)
{
    std::string s;
    if (!d || !off || off >= d->Size)
        return s;
    const char* q = (const char*)d + off;
    while (*q == ' ' || *q == '\t')
        q++;
    while (*q)
        s.push_back(*q++);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

const wchar_t* BusTypeName(STORAGE_BUS_TYPE t)
{
    switch (t)
    {
    case BusTypeUsb:               return L"USB";
    case BusTypeNvme:              return L"NVMe";
    case BusTypeSata:              return L"SATA";
    case BusTypeAta:               return L"PATA";
    case BusTypeAtapi:             return L"ATAPI";
    case BusTypeSas:               return L"SAS";
    case BusTypeScsi:              return L"SCSI";
    case BusTypeSd:                return L"SD";
    case BusTypeMmc:               return L"MMC";
    case BusTypeVirtual:           return L"virtual";
    case BusTypeFileBackedVirtual: return L"vhd";
    case BusTypeSpaces:            return L"storage-spaces";
    case BusTypeRAID:              return L"raid";
    default:                       return L"other";
    }
}

void PrintCpu()
{
    std::wstring base = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    std::wstring name = RegGetString(HKEY_LOCAL_MACHINE, base, L"ProcessorNameString");
    if (name.empty())
        name = L"(unknown)";
    while (!name.empty() && name.back() == L' ')
        name.pop_back();

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    DWORD mhz = 0, sz = sizeof(mhz), ty = 0;
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &k) == ERROR_SUCCESS)
    {
        RegQueryValueExW(k, L"~MHz", NULL, &ty, (BYTE*)&mhz, &sz);
        RegCloseKey(k);
    }

    Out(L"cpu           : %s\n", name.c_str());
    if (mhz >= 1000)
        Out(L"cpu clock     : ~%.2f GHz\n", mhz / 1000.0);
    Out(L"cpu threads   : %lu logical\n", (unsigned long)si.dwNumberOfProcessors);
}

void PrintBoard()
{
    std::wstring bios = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    std::wstring sysMfr = RegGetString(HKEY_LOCAL_MACHINE, bios, L"SystemManufacturer");
    std::wstring sysProd = RegGetString(HKEY_LOCAL_MACHINE, bios, L"SystemProductName");
    std::wstring bbMfr = RegGetString(HKEY_LOCAL_MACHINE, bios, L"BaseBoardManufacturer");
    std::wstring bbProd = RegGetString(HKEY_LOCAL_MACHINE, bios, L"BaseBoardProduct");
    std::wstring biosVer = RegGetString(HKEY_LOCAL_MACHINE, bios, L"BIOSVersion");

    if (bbMfr.empty() && bbProd.empty())
        Out(L"motherboard   : (not exposed by this environment)\n");
    else
        Out(L"motherboard   : %s %s\n", bbMfr.c_str(), bbProd.c_str());

    if (!sysMfr.empty() || !sysProd.empty())
        Out(L"system model  : %s %s\n", sysMfr.c_str(), sysProd.c_str());

    if (!biosVer.empty())
        Out(L"bios          : %s\n", biosVer.c_str());
}

struct GpuEntry
{
    std::wstring desc;
    std::wstring matchId;
    bool present;
    std::wstring renamedTo;
    std::wstring problem;
};

std::wstring StripInfPrefix(const std::wstring& s)
{
    size_t semi = s.find(L';');
    if (semi != std::wstring::npos && semi + 1 < s.size())
        return s.substr(semi + 1);
    return s;
}

std::vector<std::wstring>& LivePciIds()
{
    static std::vector<std::wstring> ids;
    static bool done = false;
    if (!done)
    {
        done = true;
        ULONG len = 0;
        if (CM_Get_Device_ID_List_SizeW(&len, L"PCI",
                                        CM_GETIDLIST_FILTER_ENUMERATOR) == CR_SUCCESS && len)
        {
            std::vector<wchar_t> buf(len);
            if (CM_Get_Device_ID_ListW(L"PCI", buf.data(), len,
                                       CM_GETIDLIST_FILTER_ENUMERATOR) == CR_SUCCESS)
            {
                for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1)
                    ids.push_back(p);
            }
        }
    }
    return ids;
}

std::wstring LowerCopy(std::wstring s)
{
    for (size_t i = 0; i < s.size(); i++)
        s[i] = (wchar_t)towlower(s[i]);
    return s;
}

std::wstring FindPresentInstance(const std::wstring& mid)
{
    if (mid.empty())
        return std::wstring();

    std::wstring want = LowerCopy(mid);
    std::vector<std::wstring>& live = LivePciIds();
    for (size_t i = 0; i < live.size(); i++)
    {
        std::wstring id = LowerCopy(live[i]);
        size_t slash = id.rfind(L'\\');
        if (slash == std::wstring::npos)
            continue;
        std::wstring hw = id.substr(0, slash);
        bool exact = (hw == want);
        bool partial = (hw.size() > want.size() &&
                        hw.compare(0, want.size(), want) == 0 &&
                        hw[want.size()] == L'&');
        if (exact || partial)
            return live[i];
    }
    return std::wstring();
}

void AnalyzeGpuEntry(GpuEntry& g)
{
    g.present = false;
    g.renamedTo.clear();
    g.problem.clear();
    if (g.matchId.empty())
        return;

    std::wstring inst = FindPresentInstance(g.matchId);
    if (inst.empty())
        return;

    DEVINST dn = 0;
    if (CM_Locate_DevNodeW(&dn, (DEVINSTID_W)inst.c_str(),
                           CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
        return;

    ULONG st = 0, prob = 0;
    if (CM_Get_DevNode_Status(&st, &prob, dn, 0) != CR_SUCCESS)
        prob = 0;

    if (prob == CM_PROB_PHANTOM || prob == kProbNotPresent)
        return;

    g.present = true;

    wchar_t pb[64];
    switch (prob)
    {
    case 0:
        break;
    case CM_PROB_DISABLED:
        g.problem = L"(disabled in bios/device manager)";
        break;
    case CM_PROB_FAILED_START:
        g.problem = L"(failed to start - driver issue)";
        break;
    case kProbNoDriver:
        g.problem = L"(no driver installed)";
        break;
    default:
        swprintf(pb, 64, L"(problem code %lu)", (unsigned long)prob);
        g.problem = pb;
        break;
    }

    std::wstring enumKey = L"SYSTEM\\CurrentControlSet\\Enum\\" + inst;
    std::wstring friendly = RegGetString(HKEY_LOCAL_MACHINE, enumKey, L"FriendlyName");
    std::wstring devDesc = StripInfPrefix(
        RegGetString(HKEY_LOCAL_MACHINE, enumKey, L"DeviceDesc"));
    if (!friendly.empty() && !devDesc.empty() &&
        _wcsicmp(friendly.c_str(), devDesc.c_str()) != 0)
        g.renamedTo = friendly;
}

void PrintGpu()
{
    std::vector<GpuEntry> gpus;

    static const wchar_t* cls =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e968-e325-11ce-bfc1-08002be10318}";
    for (int i = 0; i < 32; i++)
    {
        wchar_t sub[12];
        swprintf(sub, 12, L"%04d", i);
        std::wstring key = std::wstring(cls) + L"\\" + sub;
        GpuEntry g;
        g.desc = RegGetString(HKEY_LOCAL_MACHINE, key.c_str(), L"DriverDesc");
        if (g.desc.empty())
            continue;
        g.matchId = RegGetString(HKEY_LOCAL_MACHINE, key.c_str(), L"MatchingDeviceId");
        bool dup = false;
        for (size_t j = 0; j < gpus.size(); j++)
            if (_wcsicmp(gpus[j].matchId.c_str(), g.matchId.c_str()) == 0)
                dup = true;
        if (!dup)
        {
            AnalyzeGpuEntry(g);
            gpus.push_back(g);
        }
    }

    if (gpus.empty())
    {
        DISPLAY_DEVICEW dd;
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
        for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, &dd, 0); i++)
        {
            if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP))
                continue;
            bool dup = false;
            for (size_t j = 0; j < gpus.size(); j++)
                if (_wcsicmp(gpus[j].desc.c_str(), dd.DeviceString) == 0)
                    dup = true;
            if (!dup && dd.DeviceString[0])
            {
                GpuEntry g;
                g.desc = dd.DeviceString;
                g.present = true;
                gpus.push_back(g);
            }
        }
    }

    if (gpus.empty())
        Out(L"gpu           : (none found)\n");
    for (size_t i = 0; i < gpus.size(); i++)
    {
        Out(L"gpu[%zu]       : %s\n", i, gpus[i].desc.c_str());
        if (!gpus[i].present)
            Out(L"              : (ghost entry - hardware not present)\n");
        else
            Out(L"              : [active]%s\n",
                gpus[i].problem.empty() ? L"" : gpus[i].problem.c_str());
        if (!gpus[i].renamedTo.empty())
            Out(L"              : [renamed] device shows as \"%s\"\n",
                gpus[i].renamedTo.c_str());
    }
}

void PrintDisks()
{
    int shown = 0;
    for (int d = 0; d < 32; d++)
    {
        wchar_t dev[64];
        swprintf(dev, 64, L"\\\\.\\PhysicalDrive%d", d);
        HANDLE h = CreateFileW(dev, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        BYTE prop[4096];
        ZeroMemory(prop, sizeof(prop));
        STORAGE_PROPERTY_QUERY spq;
        spq.PropertyId = StorageDeviceProperty;
        spq.QueryType = PropertyStandardQuery;
        DWORD got = 0;
        BOOL okProp = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                      &spq, sizeof(spq),
                                      prop, sizeof(prop), &got, NULL);

        LARGE_INTEGER sizeBytes;
        sizeBytes.QuadPart = 0;
        BYTE geo[sizeof(DISK_GEOMETRY_EX) + 64];
        ZeroMemory(geo, sizeof(geo));
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                            NULL, 0, geo, sizeof(geo), &got, NULL))
            sizeBytes = ((DISK_GEOMETRY_EX*)geo)->DiskSize;

        CloseHandle(h);

        double gb = sizeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
        if (gb <= 0.01)
            continue;

        const STORAGE_DEVICE_DESCRIPTOR* desc =
            (const STORAGE_DEVICE_DESCRIPTOR*)prop;
        std::string ven = okProp ? OffsetString(desc, desc->VendorIdOffset) : "";
        std::string prod = okProp ? OffsetString(desc, desc->ProductIdOffset) : "";
        std::string rev = okProp ? OffsetString(desc, desc->ProductRevisionOffset) : "";

        STORAGE_BUS_TYPE bus = BusTypeUnknown;
        if (okProp)
            bus = desc->BusType;
        Out(L"disk%-10zu: %7.1f GB %-15s", (size_t)d, gb, BusTypeName(bus));
        if (!ven.empty() || !prod.empty())
            Out(L"%hs %hs", ven.c_str(), prod.c_str());
        if (!rev.empty())
            Out(L" (%hs)", rev.c_str());
        Out(L"\n");
        shown++;
    }
    if (!shown)
        Out(L"disks         : (none accessible in this environment)\n");
}

}

void PrintHardwareInfo()
{
    Out(L"--- hardware -------------------------------------------\n");
    PrintCpu();
    PrintBoard();
    PrintGpu();
    PrintDisks();
    Out(L"---------------------------------------------------------\n");
}
