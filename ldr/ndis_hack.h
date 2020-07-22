#pragma once

#include "hack.h"
#include "imports_dict.h"

class iat_mod: public arm64_hack
{
  public:
    iat_mod(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : arm64_hack(pe, ed)
    {
      m_iat = iat;
    }
   protected:
    int is_inside_IAT(PBYTE) const;
    int is_iat_func(PBYTE, const char *) const;
    DWORD get_iat_by_name(const char *) const;

    module_import *m_iat;
};

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
};