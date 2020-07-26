#pragma once

#include "iat_mod.h"

class combase_hack: public iat_mod
{
  public:
    combase_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : iat_mod(pe, ed, iat)
    {
      zero_data();
    }
    virtual ~combase_hack()
    { }
    int hack(int verbose);
    void dump() const;
  protected:
    void zero_data();
    int resolve_gfEnableTracing(PBYTE);
    // output data
    PBYTE m_gfEnableTracing;
    PBYTE tlg_PoFAggregate;
    std::list<PBYTE> tlg_CombaseTraceLoggingProviderProv;
    std::set<PBYTE> m_wpp;
};