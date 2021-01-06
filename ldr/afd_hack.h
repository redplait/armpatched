#pragma once

#include "iat_mod.h"

class afd_hack: public iat_mod
{
  public:
    afd_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : iat_mod(pe, ed, iat)
    {
      zero_data();
    }
    virtual ~afd_hack()
    { }
    int hack(int verbose);
    void dump() const;
    // validators
    inline int is_wsk_ok() const
    {
      return (m_AfdWskClientSpinLock != NULL) &&
             (m_AfdWskClientListHead != NULL) &&
             (m_wsk_size != 0)
      ;
    }
    inline int is_endpoints_ok() const
    {
       return (m_AfdEndpointListHead != NULL) &&
              (m_AfdGlobalData != NULL)
       ;
    }
  protected:
    void zero_data();
    void reset_wsk();
    void reset_endp();
    int find_wsk(PBYTE mz);
    int find_endpoints(PBYTE mz);
    // output data for wsk clients
    DWORD m_wsk_size;
    PBYTE m_AfdWskClientSpinLock;
    PBYTE m_AfdWskClientListHead;
    // from AfdCommonAddAddressHandler
    PBYTE m_AfdEndpointListHead;
    PBYTE m_AfdGlobalData;
    // tlg
    PBYTE afd_tlg;
};
