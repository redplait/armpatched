#pragma once

#include "hack.h"

// common base class for etw/tlg parsing
class etw_umod: public arm64_hack
{
  public:
    etw_umod(arm64_pe_file *pe, exports_dict *ed)
     : arm64_hack(pe, ed)
    {
      etw_zero_data();
    }
  protected:
    void etw_zero_data()
    { }
    // main method to find simple registered guid - like in rpcrt4_hack.h
    int find_simple_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
    // internal methods
    int find_etw_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
    int resolve_etw(PBYTE aux_guid, PBYTE mz, PBYTE &out_res);
    int disasm_etw(PBYTE psp, PBYTE aux_addr, PBYTE &out_res);
};