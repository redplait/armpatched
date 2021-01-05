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
  protected:
    void zero_data();
    int find_wsk(PBYTE mz);
    // output data
    DWORD m_wsk_size;
    PBYTE m_AfdWskClientSpinLock;
    PBYTE m_AfdWskClientListHead;
    // tlg
    PBYTE afd_tlg;
};
