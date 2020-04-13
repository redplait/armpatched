#pragma once

#include "hack.h"
#include "imports_dict.h"

class drv_hack: public arm64_hack
{
  public:
    drv_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : arm64_hack(pe, ed)
    {
      m_iat = iat;
    }
   protected:
    int is_inside_IAT(PBYTE) const;
    int is_iat_func(PBYTE, const char *) const;

    module_import *m_iat;
};

class ndis_hack: public drv_hack
{
  public:
    ndis_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : drv_hack(pe, ed, m_iat)
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
    module_import *m_iat;
    // output data
    PBYTE m_ndisProtocolListLock;
    PBYTE m_ndisProtocolList;
    PBYTE m_ndisFilterDriverListLock;
    PBYTE m_ndisFilterDriverList;
};