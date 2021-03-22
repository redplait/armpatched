#pragma once

#include "iat_mod.h"
#include "tpool.h"

struct found_xref
{
  PBYTE pfunc;
  const char *exported; // in not exported - will be NULL
  DWORD exported_ord;
  std::string section_name; // in which section this function located
  std::string yara_rule;
  int in_fids_table;    // found function presents in load_config.GuardCFFunctionTable
  int stg_index;

  int is_exported() const
  {
    return (exported != NULL) || exported_ord;
  }
  int ord_prefix() const
  {
    if ( exported == NULL )
      return 0;
     return (exported[0] == 'o') && (exported[1] == 'r') && (exported[2] == 'd');
  }
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
    int is_processed(PBYTE);
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
    int is_processed(PBYTE);
  protected:
    std::mutex m_mutex;
};

typedef enum
{
  // section name setted with section directive
  load = 0,
  store,
  ldrb,
  ldrh,
  strb,
  strh,
  // versions with explicit section name (stored in name)
  sload,
  sstore,
  sldrb,
  sldrh,
  sstrb,
  sstrh,
  // versions with global storage - index in stg_index
  gload,
  gstore,
  gldrb,
  gldrh,
  gstrb,
  gstrh,  
  ldr_off,  // load constant from pool
  limp,     // load from [IAT]
  call_imp, // [IAT] call
  call_dimp, // [delayed IAT] call
  call_exp, // call of some exported function
  call,     // just some call, perhaps in section name, may be stored in m_stg
  gcall,    // call to early remembered address in m_stg
  ldr_cookie, // load security_cookie
  call_icall, // call load_config.GuardCFCheckFunctionPointer
  ldr_rdata,  // load 8 byte constant from .rdata section
  ldr_guid,   // almost the same as ldr_rdata but for GUID in "guid" field
  ldrx,       // ldr regXX, reg, imm. index of register in reg_index
  strx,       // str regXX, reg, imm. index of register in reg_index
  addx,       // add regXX, reg, imm. index of register in reg_index
  movx,       // mov regXX, imm. index of register in reg_index
} path_item_type;

struct path_item
{
  DWORD rva;
  path_item_type type;
  union
  {
    DWORD value;     // for ldr_off
    BYTE  rconst[8]; // for ldr_rdata
    BYTE  guid[16];  // for ldr_guid
  };
  DWORD value_count; // count of value in this section for ldr_off, in .rdata for ldr_rdata/ldr_guid
  int reg_index;
  // attributes
  DWORD stg_index;
  int wait_for;
  std::string name; // for call_imp/call_exp/limp

  // constructors
  path_item() = default;
  path_item(path_item_type t, DWORD arva)
  {
    type = t;
    rva = arva;
    reg_index = 0;
    value_count = 0;
    stg_index = 0;
    wait_for = 0;
  }
  template <typename T>
  path_item(std::initializer_list<T> l)
  {
    if ( l.size() == 16 )
      type = ldr_guid;
    else
      type = ldr_rdata;
    value_count = 0;
    stg_index = 0;
    wait_for = 0;
    size_t i;
    for ( i = 0; i < _countof(rconst); i++ )
      rconst[i] = 0;
    i = 0;
    if ( type == ldr_rdata )
      for ( auto const li = l.cbegin(); li != l.cend() && i < _countof(rconst); ++li, i++ )
        rconst[i] = (BYTE)*li;
    else
      for ( auto const li = l.cbegin(); li != l.cend() && i < _countof(guid); ++li, i++ )
        guid[i] = (BYTE)*li;
  }
  path_item(DWORD val)
  {
    type = ldr_off;
    value_count = 0;
    value = val;
    reg_index = 0;
    stg_index = 0;
    wait_for = 0;
  }

  void reset();
  void dump() const;
  void pod_dump(FILE *fp) const;
  int is_load_store() const;
  bool operator==(const path_item&) const;
};

class path_edge
{
  public:
   std::string symbol_section;
   std::list<path_item> list;
   bool operator<(const path_edge& s) const
   {
     return list.size() < s.list.size();
   }
   bool operator==(const path_edge &other) const
   {
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
   int contains_limp(std::string &) const;
   int is_dimp1_only(std::string &) const;
   int contains_dimp(std::string &) const;
   int has_const_count(int below) const;
   int has_rconst_count(int below) const;
   int has_stg() const
   {
     return std::any_of(list.cbegin(), list.cend(), [=](const path_item &item) -> bool { return item.stg_index != 0; });
   }
   int can_reduce() const;
   int reduce();
   void reset()
   {
     std::for_each(list.begin(), list.end(), [](path_item &item){ item.reset(); });
   }
   const path_item *get_best_const() const;
   const path_item *get_best_rconst() const;
   int collect_limps(std::set<std::string> &) const;
   int collect_call_imps(std::set<std::string> &) const;
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
    inline PBYTE base_addr() const
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
    void prepare(found_xref &xref, path_edge &);
    inline const std::map<DWORD, DWORD> &get_stg() const
    {
      return m_stg;
    }
    // yara results
    std::map<std::string, std::set<DWORD> > yara_results;
  protected:
    const char *get_exported(PBYTE mz, PBYTE) const;
    int store_op(path_item_type t, const one_section *s, PBYTE pattern, PBYTE what, path_edge &edge);
    void calc_const_count(PBYTE func, path_edge &);
    void calc_const_count_in_section(const char *, path_edge &);
    void calc_const_count(const one_section *, path_edge &);
    void calc_rdata_count(path_edge &);
    int try_apply(const one_section *s, PBYTE psp, path_edge &, DWORD &found);
    void store_stg(DWORD index, DWORD value);
    // global storage
    std::map<DWORD, DWORD> m_stg;
    std::map<DWORD, DWORD> m_stg_copy;
};

// set of test files
class deriv_tests
{
  public:
   struct deriv_test
   {
     std::wstring fname;
     arm64_pe_file *pe;
     inmem_import_holder i_h;
     inmem_import_holder di_h; // delayed import holder
     deriv_hack *der;
     deriv_test(deriv_test &&outer)
       : i_h(std::move(outer.i_h)),
         di_h(std::move(outer.di_h)),
         fname(std::move(outer.fname))
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
     deriv_test(const wchar_t *name, arm64_pe_file *f, inmem_import_holder &&ih, inmem_import_holder &&dih, deriv_hack *d)
      : pe(f),
        fname(name),
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
   int empty() const
   {
     return mods.empty();
   }
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