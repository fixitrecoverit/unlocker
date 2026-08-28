#include <winsock2.h>
#include "net.h"
#include "procs.h"
#include <iphlpapi.h>
#include <map>

namespace
{

std::wstring Ip4(DWORD ip)
{
    return L"" + std::to_wstring(ip & 0xFF) + L"." +
           std::to_wstring((ip >> 8) & 0xFF) + L"." +
           std::to_wstring((ip >> 16) & 0xFF) + L"." +
           std::to_wstring((ip >> 24) & 0xFF);
}

unsigned short Port(DWORD p)
{
    return (unsigned short)((p >> 8) | ((p & 0xffu) << 8));
}

const wchar_t* TcpStateName(DWORD s)
{
    switch (s)
    {
    case MIB_TCP_STATE_CLOSED:      return L"closed";
    case MIB_TCP_STATE_LISTEN:      return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT:    return L"syn_sent";
    case MIB_TCP_STATE_SYN_RCVD:    return L"syn_rcvd";
    case MIB_TCP_STATE_ESTAB:       return L"ESTAB";
    case MIB_TCP_STATE_FIN_WAIT1:   return L"fin_w1";
    case MIB_TCP_STATE_FIN_WAIT2:   return L"fin_w2";
    case MIB_TCP_STATE_CLOSE_WAIT:  return L"close_wait";
    case MIB_TCP_STATE_CLOSING:     return L"closing";
    case MIB_TCP_STATE_LAST_ACK:    return L"last_ack";
    case MIB_TCP_STATE_TIME_WAIT:   return L"time_wait";
    case MIB_TCP_STATE_DELETE_TCB:  return L"delete_tcb";
    default:                        return L"?";
    }
}

}

void CmdNet()
{
    std::vector<ProcEntry> procs = ListProcesses();
    std::map<DWORD, std::wstring> names;
    for (size_t i = 0; i < procs.size(); i++)
        names[procs[i].pid] = procs[i].name;

    Out(L"%sproto   state       local                 remote                process%s\n",
        col::Dim, col::R);

    DWORD sz = 0;
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET,
                            TCP_TABLE_OWNER_MODULE_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<BYTE> tb(sz);
    if (GetExtendedTcpTable(tb.data(), &sz, FALSE, AF_INET,
                            TCP_TABLE_OWNER_MODULE_ALL, 0) != ERROR_SUCCESS)
        return;

    MIB_TCPTABLE_OWNER_MODULE* t = (MIB_TCPTABLE_OWNER_MODULE*)tb.data();
    for (DWORD i = 0; i < t->dwNumEntries; i++)
    {
        const MIB_TCPROW_OWNER_MODULE& r = t->table[i];
        std::wstring proc;
        std::map<DWORD, std::wstring>::iterator it = names.find(r.dwOwningPid);
        if (it != names.end())
            proc = it->second;
        const wchar_t* color = r.dwState == MIB_TCP_STATE_ESTAB ? col::Yel
                               : r.dwState == MIB_TCP_STATE_LISTEN ? L""
                                                                   : col::Dim;
        Out(L"%stcp4    %-10s %-21s %-21s %lu%s%s%s\n", color,
            TcpStateName(r.dwState),
            (Ip4(r.dwLocalAddr) + L":" + std::to_wstring(Port(r.dwLocalPort)))
                .c_str(),
            (Ip4(r.dwRemoteAddr) + L":" +
             std::to_wstring(Port(r.dwRemotePort)))
                .c_str(),
            (unsigned long)r.dwOwningPid,
            proc.empty() ? L"" : L" ", proc.c_str(), col::R);
    }

    sz = 0;
    if (GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET,
                            UDP_TABLE_OWNER_MODULE, 0) ==
        ERROR_INSUFFICIENT_BUFFER)
    {
        std::vector<BYTE> ub(sz);
        if (GetExtendedUdpTable(ub.data(), &sz, FALSE, AF_INET,
                                UDP_TABLE_OWNER_MODULE, 0) == ERROR_SUCCESS)
        {
            MIB_UDPTABLE_OWNER_MODULE* u =
                (MIB_UDPTABLE_OWNER_MODULE*)ub.data();
            for (DWORD i = 0; i < u->dwNumEntries; i++)
            {
                const MIB_UDPROW_OWNER_MODULE& r = u->table[i];
                std::map<DWORD, std::wstring>::iterator it =
                    names.find(r.dwOwningPid);
                Out(L"%sudp4    %-10s %-21s %-21s %lu %s%s\n", col::Dim,
                    L"-",
                    (Ip4(r.dwLocalAddr) + L":" +
                     std::to_wstring(Port(r.dwLocalPort)))
                        .c_str(),
                    L"-", (unsigned long)r.dwOwningPid,
                    it != names.end() ? it->second.c_str() : L"", col::R);
            }
        }
    }
}
