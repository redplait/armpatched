#include "stdafx.h"
#include "iat_mod.h"
#include "cf_graph.h"

int iat_mod::is_inside_IAT(PBYTE psp) const
{
  if ( NULL == m_iat )
    return 0;
  return is_inside_import(psp - m_pe->base_addr(), m_iat);
}

int iat_mod::is_inside_DIAT(PBYTE psp) const
{
  if ( NULL == m_diat )
    return 0;
  return is_inside_import(psp - m_pe->base_addr(), m_diat);
}

const char *iat_mod::get_iat_func(PBYTE psp) const
{
  if ( NULL == m_iat )
    return NULL;
  return get_iat_name(psp - m_pe->base_addr(), m_iat);
}

const char *iat_mod::get_diat_func(PBYTE psp) const
{
  if ( NULL == m_diat )
    return NULL;
  return get_iat_name(psp - m_pe->base_addr(), m_diat);
}

int iat_mod::is_iat_func(PBYTE psp, const char *name) const
{
  if ( NULL == m_iat )
    return 0;
  return is_iat_func(m_iat, psp - m_pe->base_addr(), name);
}

int iat_mod::is_diat_func(PBYTE psp, const char *name) const
{
  if ( NULL == m_diat )
    return 0;
  return is_iat_func(m_diat, psp - m_pe->base_addr(), name);
}

DWORD iat_mod::get_iat_by_name(const char *name) const
{
  if ( NULL == m_iat )
    return NULL;
  DWORD addr = m_iat->iat_rva;
  for ( DWORD index = 0; index < m_iat->iat_count; index++, addr += ptr_size )
  {
    if ( m_iat->iat[index].name == NULL )
      continue;
    if ( !strcmp(m_iat->iat[index].name, name) )
      return addr;
  }
  return 0;
}

DWORD iat_mod::get_diat_by_name(const char *name) const
{
  if ( NULL == m_diat )
    return NULL;
  DWORD addr = m_diat->iat_rva;
  for ( DWORD index = 0; index < m_diat->iat_count; index++, addr += ptr_size )
  {
    if ( m_diat->iat[index].name == NULL )
      continue;
    if ( !strcmp(m_diat->iat[index].name, name) )
      return addr;
  }
  return 0;
}

//
// wpp extract logic
//
int iat_mod::is_wpp_glob(PBYTE addr)
{
  if ( !in_section(addr, ".data") )
    return 0;
  uint64 value = *(uint64 *)addr;
  // WPP_GLOBAL_Control DCQ WPP_GLOBAL_Control
  return (value == (uint64)addr);
}

int iat_mod::find_wpps(PBYTE mz, std::set<PBYTE> &out_res)
{
  int res = 0;
  DWORD off = get_iat_by_name("EtwRegisterTraceGuidsW");
  if ( off )
  {
    if ( m_verbose )
      printf("EtwRegisterTraceGuidsW: %X\n", off);
    res += hack_one_imported(mz, mz + off, "EtwRegisterTraceGuidsW", out_res);
  }
  off = get_iat_by_name("EtwRegisterTraceGuidsA");
  if ( off )
  {
    if ( m_verbose )
      printf("EtwRegisterTraceGuidsA: %X\n", off);
    res += hack_one_imported(mz, mz + off, "EtwRegisterTraceGuidsA", out_res);
  }
  // RegisterTraceGuids
  off = get_iat_by_name("RegisterTraceGuidsW");
  if ( off )
  {
    if ( m_verbose )
      printf("RegisterTraceGuidsW: %X\n", off);
    res += hack_one_imported(mz, mz + off, "RegisterTraceGuidsW", out_res);
  }
  off = get_iat_by_name("RegisterTraceGuidsA");
  if ( off )
  {
    if ( m_verbose )
      printf("RegisterTraceGuidsA: %X\n", off);
    res += hack_one_imported(mz, mz + off, "RegisterTraceGuidsA", out_res);
  }
  return res;
}

int iat_mod::hack_one_imported(PBYTE mz, PBYTE psp, const char *fname, std::set<PBYTE> &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  xref_finder xf;
  std::list<PBYTE> refs;
  int res = xf.find(mz + s->va, s->size, psp, refs);
  if ( !res )
    return 0;
  res = 0;
  std::set<PBYTE> func_cache;
  for ( auto citer = refs.cbegin(); citer != refs.cend(); ++citer )
  {
    PBYTE func = find_pdata(*citer);
    if ( NULL == func )
    {
      if ( m_verbose )
        printf("cannot find function for %s at %p\n", fname, PVOID(*citer - mz));
      continue;
    }
    auto found = func_cache.find(func);
    if ( found != func_cache.end() )
      continue;
    if ( m_verbose )
      printf("function at %p for %s\n", PVOID(func - mz), fname);
    int tmp = hack_wpp_func(func, psp, out_res);
    // add to cache
    try
    {
      func_cache.insert(func);
    } catch(std::bad_alloc)
    { break; }
    // check result    
    if ( tmp )
    {
      res += tmp;
      continue;
    }
  }
  return res;
}

int iat_mod::hack_wpp_func(PBYTE psp, PBYTE what, std::set<PBYTE> &out_res)
{
  statefull_graph<PBYTE, regs_pad> cgraph;
  std::list<std::pair<PBYTE, regs_pad> > addr_list;
  regs_pad tmp;
  auto curr = std::make_pair(psp, tmp);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  int res = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
    {
      psp = iter->first;
      if ( m_verbose )
        printf("hack_wpp_func: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      PBYTE self_reffed = NULL;
      PBYTE main_cb = NULL;
      for ( ; ; )
      {
        if ( !disasm() || is_ret() )
          break;
        if ( check_jmps(cgraph, iter->second) )
          continue;
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr, iter->second);
          break;
        }
        if ( is_br_reg() )
        {
          PBYTE what = (PBYTE)iter->second.get(get_reg(0));
          if ( what != NULL && in_executable_section(what) )
             cgraph.add(what, iter->second);
          break;
        }
        if ( is_adrp(iter->second) )
          continue;
        if ( is_ldar(iter->second) )
          continue;
        if ( is_mov_rr(iter->second) )
          continue;
        if ( is_add() )
        {
          iter->second.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        // check str
        if ( is_str() )
        {
          PBYTE what = (PBYTE)iter->second.get(get_reg(1)) + m_dis.operands[2].op_imm.bits;
          if ( is_wpp_glob(what) )
          {
            self_reffed = what;
            main_cb = (PBYTE)iter->second.get(get_reg(0));
          }
        }
        if ( is_ldr() )
        {
          PBYTE data = (PBYTE)iter->second.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( NULL == data || !m_pe->is_inside(data) )
            continue;
          if (is_wpp_glob(data))
          {
            self_reffed = data;
            continue;
          }
          PBYTE deref = (PBYTE)*((reg64_t *)data);
          if ( NULL == deref || !m_pe->is_inside(deref) )
            continue;
          iter->second.adrp(get_reg(0), (reg64_t)deref);
          continue;
        }
        // check for blr
        if ( is_bl_reg() )
        {
          PBYTE call_addr = (PBYTE)iter->second.get(get_reg(0));
          if ( call_addr == what )
          {
            /* see https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-registertraceguidsa
                ULONG WMIAPI RegisterTraceGuidsA(
  		WMIDPREQUEST             RequestAddress,
  		PVOID                    RequestContext,
  		LPCGUID                  ControlGuid,
  		ULONG                    GuidCount,
  		PTRACE_GUID_REGISTRATION TraceGuidReg,
  		LPCSTR                   MofImagePath,
  		LPCSTR                   MofResourceName,
  	    x7 - PTRACEHANDLE             RegistrationHandle
  	     */
            PBYTE data = (PBYTE)iter->second.get(AD_REG_X7);
            if ( data == NULL )
              continue;
            if ( data == main_cb + 8 )
            {
              try
              {
                out_res.insert(self_reffed);
                res++;
              } catch(std::bad_alloc)
              { return res; }
              continue;
            }
            // for functions like WppInitUm I know only WPP_GLOBAL_Control and x7 must point to self_reffed + 8
            if ( (self_reffed != NULL) && (data == self_reffed + 8) )
            {
              try
              {
                out_res.insert(self_reffed);
                res++;
              } catch(std::bad_alloc)
              { return res; }
              continue;
            }
          }
        }
      }
      cgraph.add_range(psp, m_psp - psp);
    }
    // prepare for next edge generation
    edge_gen++;
    if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
      break;    
  }
  return res;
}