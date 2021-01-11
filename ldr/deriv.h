#pragma once

#include "iat_mod.h"

struct found_xref
{
  PBYTE pfunc;
  const char *exported; // in not exported - will be NULL
  std::string section_name; // in which section this function located
};

class funcs_holder_cmn
{
  public:
    funcs_holder_cmn(arm64_hack *pe)
      : m_pe(pe)
    { }
    // not thread-safe methods
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

class funcs_holder: public funcs_holder_cmn
{
  public:
    funcs_holder(arm64_hack *pe)
     : funcs_holder_cmn(pe)
    { }
    void add(PBYTE);
    void add_processed(PBYTE);
};

// thread-safe version
class funcs_holder_ts: public funcs_holder_cmn
{
  public:
    funcs_holder_ts(arm64_hack *pe)
     : funcs_holder_cmn(pe)
    { }
    // thread-safe methods
    void add(PBYTE);
    void add_processed(PBYTE);
  protected:
    std::mutex m_mutex;
};

typedef enum
{
  load = 0,
  store,
  ldrb,
  ldrh,
  strb,
  strh,
  ldr_off,  // some constant
  call_imp, // [IAT] call
  call_exp, // call of some exported function
} path_item_type;

struct path_item
{
  path_item_type type;
  DWORD value; // for ldr_off
  DWORD value_count; // count of value in this section
  std::string name; // for call_imp/call_exp

  void dump() const;
  int is_load_store() const;
};

class path_edge
{
  public:
   std::list<path_item> list;
   path_item last;
   bool operator<(const path_edge& s) const
   {
     return list.size() < s.list.size();
   }
   int is_trivial() const
   {
     return std::all_of(list.cbegin(), list.cend(), [](const path_item &item){ return item.is_load_store(); });
   }
   int is_imp1_only(std::string &) const;
   int contains_imp(std::string &) const;
   int has_const_count(int below) const;
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
    int make_path(DWORD rva, PBYTE func, path_edge &);
  protected:
    void check_exported(PBYTE mz, found_xref &) const;
    const char *get_exported(PBYTE mz, PBYTE) const;
    template <typename FH>
    int disasm_one_func(PBYTE addr, PBYTE what, FH &fh);
    int store_op(path_item_type t, const one_section *s, PBYTE pattern, PBYTE what, path_edge &edge);
    void calc_const_count(PBYTE func, path_edge &);
};