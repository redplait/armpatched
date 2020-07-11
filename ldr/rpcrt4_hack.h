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
    // output data
    PBYTE m_RpcHasBeenInitialized;
    PBYTE m_GlobalRpcServer;
    DWORD m_ForwardFunction_offset;
    // from RpcMgmtSetAuthorizationFn
    PBYTE m_MgmtAuthorizationFn;
    // etw guts
    PBYTE m_RpcLegacyEvents_Context;
    PBYTE m_Networking_CorrelationHandle;
};