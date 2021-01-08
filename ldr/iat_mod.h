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
    inline int hack_wpp(std::set<PBYTE> &out_res, int verbose = 0)
    {
      m_verbose = verbose;
      return find_wpps(m_pe->base_addr(), out_res);
    }
   protected:
    int is_inside_IAT(PBYTE) const;
    int is_iat_func(PBYTE, const char *) const;
    const char *get_iat_func(PBYTE) const;
    DWORD get_iat_by_name(const char *) const;
    // wpp methods
    int find_wpps(PBYTE mz, std::set<PBYTE> &);
    int hack_one_imported(PBYTE mz, PBYTE psp, const char *fname, std::set<PBYTE> &);
    int is_wpp_glob(PBYTE);
    int hack_wpp_func(PBYTE func, PBYTE what, std::set<PBYTE> &out_res);

    module_import *m_iat;
};
