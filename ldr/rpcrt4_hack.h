#pragma once

#include "etw_umod.h"

class rpcrt4_hack: public etw_umod
{
  public:
    rpcrt4_hack(arm64_pe_file *pe, exports_dict *ed)
     : etw_umod(pe, ed)
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