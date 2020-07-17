#pragma once

#include "etw_umod.h"

class combase_hack: public etw_umod
{
  public:
    combase_hack(arm64_pe_file *pe, exports_dict *ed)
     : etw_umod(pe, ed)
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
    PBYTE tlg_CombaseTraceLoggingProviderProv;
};