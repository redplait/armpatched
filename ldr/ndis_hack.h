#pragma once
#include "iat_mod.h"

class ndis_hack: public iat_mod
{
  public:
    ndis_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : iat_mod(pe, ed, iat)
    {
      zero_data();
    }
    virtual ~ndis_hack()
    { }
    int hack(int verbose);
    void dump() const;
  protected:
    void zero_data();
    void collect_calls(PBYTE psp, std::set<PBYTE> &, const char *s_name);
    int hack_lock_list(PBYTE psp, DWORD num, PBYTE &lock, PBYTE &list);
    int hack_alloc(PBYTE psp, DWORD tag, DWORD &out_size);
    int hack_alloc_ext(PBYTE psp, DWORD &out_size);
    int find_ndisFindMiniportOnGlobalList(PBYTE psp, PBYTE &out_res);
    int hack_miniports(PBYTE psp);
    // output data
    PBYTE m_ndisProtocolListLock;
    PBYTE m_ndisProtocolList;
    DWORD NDIS_PROTOCOL_BLOCK_size;
    // from NdisFRegisterFilterDriver
    PBYTE m_ndisFilterDriverListLock;
    PBYTE m_ndisFilterDriverList;
    // from NdisMRegisterMiniportDriver
    PBYTE m_ndisMiniDriverListLock;
    PBYTE m_ndisMiniDriverList;
    DWORD NDIS_M_DRIVER_BLOCK_size;
    // miniports - from ndisFindMiniportOnGlobalList
    PBYTE m_ndisMiniportListLock;
    PBYTE m_ndisMiniportList;
    DWORD m_NextGlobalMiniport;
    // ndis!_NDIS_COMMON_OPEN_BLOCK - from NdisOpenAdapterEx
    PBYTE m_ndisGlobalOpenListLock;
    PBYTE m_ndisGlobalOpenList;
    // tlg data
    PBYTE tlg_TelemetryAssert;
    PBYTE tlg_TelemetryAssertDiagTrack;
    PBYTE tlg_TelemetryAssertDiagTrack_KM;
};