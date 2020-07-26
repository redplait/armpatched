#pragma once

#include "iat_mod.h"

class rpc_hack: public iat_mod
{
  public:
    rpc_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : iat_mod(pe, ed, iat)
    {
    }
    int hack(int verbose);
    void dump() const;
   protected:
    int hack_one_import(PBYTE mz, PBYTE addr, const char *fname);
    int hack_one_func(PBYTE func, PBYTE what);
    int hack_caller(PBYTE func, PBYTE what);
    int is_already_stored(const GUID *, PBYTE);
    std::list<std::pair<GUID, PBYTE> > m_out_res;
};