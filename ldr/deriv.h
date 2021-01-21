#pragma once

#include "iat_mod.h"
#include "tpool.h"

struct found_xref
{
  PBYTE pfunc;
  const char *exported; // in not exported - will be NULL
  std::string section_name; // in which section this function located
  int in_fids_table;    // found function presents in load_config.GuardCFFunctionTable
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
    int exchange(std::set<PBYTE> &);
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
    int exchange(std::set<PBYTE> &);
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
  ldr_cookie, // load security_cookie
  call_icall, // call load_config.GuardCFCheckFunctionPointer
} path_item_type;

struct path_item
{
  DWORD rva;
  path_item_type type;
  DWORD value; // for ldr_off
  DWORD value_count; // count of value in this section
  std::string name; // for call_imp/call_exp

  void dump() const;
  int is_load_store() const;
  bool operator==(const path_item&) const;
};

class path_edge
{
  public:
   std::string symbol_section;
   std::list<path_item> list;
   path_item last;
   bool operator<(const path_edge& s) const
   {
     return list.size() < s.list.size();
   }
   bool operator==(const path_edge &other) const
   {
     if ( !(last == other.last) )
       return false;
     if ( list.size() != other.list.size() )
       return false;
     // compare lists
     return std::equal(list.cbegin(), list.cend(), other.list.cbegin());
   }
   int is_trivial() const
   {
     return std::all_of(list.cbegin(), list.cend(), [](const path_item &item){ return item.is_load_store(); });
   }
   int is_imp1_only(std::string &) const;
   int contains_imp(std::string &) const;
   int has_const_count(int below) const;
   int can_reduce() const;
   int reduce();
   const path_item *get_best_const() const;
};

class deriv_hack: public iat_mod
{
  public:
    deriv_hack(arm64_pe_file *pe, exports_dict *ed, module_import *iat, module_import *diat)
     : iat_mod(pe, ed, iat, diat)
    {
//      zero_data();
    }
    int resolve_section(DWORD rva, std::string &) const;
    int find_xrefs(DWORD rva, std::list<found_xref> &);
    int make_path(DWORD rva, PBYTE func, path_edge &);
    void reset_export()
    {
      m_ed = NULL;
    }
    inline PBYTE base_addr()
    {
      return m_pe->base_addr();
    }
    inline void get_pdata(DWORD &rva, DWORD &size)
    {
      rva = m_pdata_rva;
      size = m_pdata_size;
    }
    void check_exported(PBYTE mz, found_xref &) const;
    int find_in_fids_table(PBYTE mz, PBYTE func) const;
    template <typename FH>
    int disasm_one_func(PBYTE addr, PBYTE what, FH &fh);
    int apply(found_xref &xref, path_edge &, DWORD &found);
  protected:
    const char *get_exported(PBYTE mz, PBYTE) const;
    int store_op(path_item_type t, const one_section *s, PBYTE pattern, PBYTE what, path_edge &edge);
    void calc_const_count(PBYTE func, path_edge &);
    int try_apply(const one_section *s, PBYTE psp, path_edge &, DWORD &found);
};

// set of test files
class deriv_tests
{
  public:
   struct deriv_test
   {
     arm64_pe_file *pe;
     inmem_import_holder i_h;
     inmem_import_holder di_h; // delayed import holder
     deriv_hack *der;
     deriv_test(deriv_test &&outer)
       : i_h(std::move(outer.i_h)),
         di_h(std::move(outer.di_h))
     {
       pe = outer.pe;
       outer.pe = NULL;
       der = outer.der;
       outer.der = NULL;
     }
     deriv_test()
     {
       pe = NULL;
       der = NULL;
     }
     deriv_test(arm64_pe_file *f, inmem_import_holder &&ih, inmem_import_holder &&dih, deriv_hack *d)
      : pe(f),
        i_h(std::move(ih)),
        di_h(std::move(dih)),
        der(d)
     { }
     ~deriv_test()
     {
       if ( pe != NULL )
         delete pe;
       if ( der != NULL )
         delete der;
     }
   };
   std::list<deriv_test> mods;
   int add_module(const wchar_t *);
};

// multi-threaded version of deriv_hack - find own deriv_hack for every thread
class deriv_pool
{
  public:
   struct xref_res
   {
     int res;
     found_xref xref;
   };

   deriv_pool(arm64_pe_file *pe, exports_dict *ed, module_import *iat, module_import *diat, int thread_num)
     : m_tpool(thread_num),
       m_ders(thread_num, NULL)
   {
     for ( DWORD i = 0; i < thread_num; i++ )
       m_ders[i] = new deriv_hack(pe, ed, iat, diat);
   }
   ~deriv_pool()
   {
     int n = 0;
     for ( auto iter = m_ders.begin(); iter != m_ders.end(); ++iter, ++n )
     {
       if ( n )
         (*iter)->reset_export();
       delete *iter;
     }
   }
   inline deriv_hack *get_first()
   {
     return m_ders[0];
   }
   int find_xrefs(DWORD rva, std::list<found_xref> &);
  protected:
    thread_pool<xref_res> m_tpool;
    std::vector<deriv_hack *> m_ders;
};