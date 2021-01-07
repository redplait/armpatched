#pragma once

#include "iat_mod.h"

struct found_xref
{
  PBYTE addr;
  PBYTE pfunc;
  const char *exported; // in not exported - will be NULL
};

class funcs_holder
{
  public:
    funcs_holder(arm64_hack *pe)
     : m_pe(pe)
    { }
    void add(PBYTE);
    void add_processed(PBYTE);
    inline int empty() const
    {
      return m_current.empty();
    }
    int exchange(std::set<PBYTE> &);
  protected:
    std::set<PBYTE> m_current;
    std::set<PBYTE> m_processed;
    arm64_hack *m_pe;
};

class deriv_hack: public iat_mod
{
  public:
    deriv_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat)
     : iat_mod(pe, ed, iat)
    {
//      zero_data();
    }
    int find_xrefs(DWORD rva, std::list<found_xref> &);
  protected:
    void check_exported(PBYTE mz, found_xref &) const;
    int disasm_one_func(PBYTE addr, PBYTE what, funcs_holder &fh);
};