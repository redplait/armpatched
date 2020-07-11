#pragma once

#include "hack.h"

class rpcrt4_hack: public arm64_hack
{
  public:
    rpcrt4_hack(arm64_pe_file *pe, exports_dict *ed)
     : arm64_hack(pe, ed)
    {
      zero_data();
    }
    virtual ~rpcrt4_hack()
    { }
    int hack(int verbose);
    void dump() const;
  protected:
    void zero_data();
    int hack_auth_fn(PBYTE);
    int find_rpc_server(PBYTE);
    int find_etw_by_signs(PBYTE mz);
    int find_wmi_data(PBYTE);
    int find_etw_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
    int resolve_etw(PBYTE aux_guid, PBYTE mz, PBYTE &out_res);
    int disasm_etw(PBYTE psp, PBYTE aux_addr, PBYTE &out_res);
    // aux data
    PBYTE aux_RpcEtwGuid;
    PBYTE aux_RpcLegacyEvents;
    PBYTE aux_Networking_CorrelationId;
    // output data
    PBYTE m_RpcHasBeenInitialized;
    PBYTE m_GlobalRpcServer;
    DWORD m_ForwardFunction_offset;
    // from RpcMgmtSetAuthorizationFn
    PBYTE m_MgmtAuthorizationFn;
    // I_RpcEnableWmiTrace
    PBYTE m_WmiTraceData;
    // etw guts
    PBYTE m_RpcEtwGuid_Context;
    PBYTE m_RpcLegacyEvents_Context;
    PBYTE m_Networking_CorrelationHandle;
};