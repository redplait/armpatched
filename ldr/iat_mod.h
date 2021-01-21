#pragma once

#include "hack.h"
#include "imports_dict.h"

class iat_mod: public arm64_hack
{
  public:
    iat_mod(arm64_pe_file *pe, exports_dict *ed, module_import *iat, module_import *diat = NULL)
     : arm64_hack(pe, ed)
    {
      m_iat = iat;
      m_diat = diat;
    }
    inline int hack_wpp(std::set<PBYTE> &out_res, int verbose = 0)
    {
      m_verbose = verbose;
      return find_wpps(m_pe->base_addr(), out_res);
    }
   protected:
    inline int is_inside_import(ptrdiff_t off, module_import *iat) const
    {
      if ( (off >= iat->iat_rva) &&
           (off < (iat->iat_rva + iat->iat_size))
         )
        return 1;
      return 0;
    }
    inline const char *get_iat_name(ptrdiff_t off, module_import *iat) const
    {
      if ( (off >= iat->iat_rva) &&
           (off < (iat->iat_rva + iat->iat_size))
         )
      {
        size_t index = (off - iat->iat_rva) / 8;
        return iat->iat[index].name;
      }
      return NULL;
    }
    inline int is_iat_func(module_import *iat, ptrdiff_t off, const char *name) const
    {
      if ( (off >= iat->iat_rva) &&
           (off < (iat->iat_rva + iat->iat_size))
         )
      {
        size_t index = (off - iat->iat_rva) / 8;
        if ( iat->iat[index].name != NULL && !strcmp(iat->iat[index].name, name) )
          return 1;
      }
      return 0;
    }
    // methods for imports
    int is_inside_IAT(PBYTE) const;
    int is_iat_func(PBYTE, const char *) const;
    const char *get_iat_func(PBYTE) const;
    DWORD get_iat_by_name(const char *) const;
    // methods for delayed imports
    int is_inside_DIAT(PBYTE) const;
    int is_diat_func(PBYTE, const char *) const;
    const char *get_diat_func(PBYTE) const;
    DWORD get_diat_by_name(const char *) const;
    // wpp methods
    int find_wpps(PBYTE mz, std::set<PBYTE> &);
    int hack_one_imported(PBYTE mz, PBYTE psp, const char *fname, std::set<PBYTE> &);
    int is_wpp_glob(PBYTE);
    int hack_wpp_func(PBYTE func, PBYTE what, std::set<PBYTE> &out_res);

    module_import *m_iat;
    module_import *m_diat; // delayed import
};
