#include "stdafx.h"
#include "rpc_hack.h"
#include "cf_graph.h"

void rpc_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  for ( auto citer = m_out_res.cbegin(); citer != m_out_res.cend(); ++citer )
  {
    printf("%8.8X-%4.4X-%4.4X-%2.2X%2.2X-%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X at %p\n", 
      citer->first.Data1,
      citer->first.Data2, citer->first.Data3,
      citer->first.Data4[0], citer->first.Data4[1], citer->first.Data4[2], citer->first.Data4[3],
      citer->first.Data4[4], citer->first.Data4[5], citer->first.Data4[6], citer->first.Data4[7],
      PVOID(citer->second - mz)
    );
  }
}

static const char *s_if = "RpcServerRegisterIf";
static const char *s_if2 = "RpcServerRegisterIf2";
static const char *s_if3 = "RpcServerRegisterIf3";
static const char *s_ifex = "RpcServerRegisterIfEx";

int rpc_hack::hack(int verbose)
{
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  m_verbose = verbose;
  DWORD off = get_iat_by_name(s_if);
  if ( off )
  {
    if ( verbose )
      printf("%s: %X\n", s_if, off);
    res += hack_one_import(mz, mz + off, s_if);
  }
  off = get_iat_by_name(s_if2);
  if ( off ) 
  {
    if ( verbose )
      printf("%s: %X\n", s_if2, off);
    res += hack_one_import(mz, mz + off, s_if2);
  }
  off = get_iat_by_name(s_if3);
  if ( off ) 
  {
    if ( verbose )
      printf("%s: %X\n", s_if3, off);
    res += hack_one_import(mz, mz + off, s_if3);
  }
  off = get_iat_by_name(s_ifex);
  if ( off ) 
  {
    if ( verbose )
      printf("%s: %X\n", s_ifex, off);
    res += hack_one_import(mz, mz + off, s_ifex);
  }
  return res;
}

int rpc_hack::hack_one_import(PBYTE mz, PBYTE psp, const char *fname)
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
  for ( auto citer = refs.cbegin(); citer != refs.cend(); ++citer )
  {
    PBYTE func = find_pdata(*citer);
    if ( NULL == func )
    {
      if ( m_verbose )
        printf("cannot find function for %s at %p\n", fname, PVOID(*citer - mz));
      continue;
    }
    if ( m_verbose )
      printf("function at %p for %s\n", PVOID(func - mz), fname);
    int tmp = hack_one_func(func, psp);
    if ( tmp )
    {
      res += tmp;
      continue;
    }
    // ok, try to check callers of this function
    std::list<PBYTE> callers;
    if ( !xf.find_bl(mz + s->va, s->size, func, callers) )
      continue;
    for ( auto calliter = callers.cbegin(); calliter != callers.cend(); ++calliter )
    {
      PBYTE caller_func = find_pdata(*calliter);
      if ( NULL == caller_func )
        continue;
      res += hack_caller(caller_func, func);
    }
  }
  return res;
}

int rpc_hack::hack_caller(PBYTE psp, PBYTE what)
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
        printf("rpc_hack::hack_caller: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
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
        if ( is_add() )
        {
          iter->second.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        // check for blr
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) && (caddr == what) )
        {
           PBYTE data = (PBYTE)iter->second.get(AD_REG_X0);
           if ( data == NULL || !m_pe->is_inside(data) )
             continue;
           // check size
           if ( 0x60 != *(PDWORD)data )
             continue;
           try
           {
             GUID *tmp_guid = (GUID *)(data + 4);
             auto pair = std::make_pair(*tmp_guid, data);
             m_out_res.push_back(pair);
             res++;
           } catch(std::bad_alloc)
           { return res; }
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

int rpc_hack::hack_one_func(PBYTE psp, PBYTE what)
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
        printf("rpc_hack::hack_one_func: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
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
        if ( is_add() )
        {
          iter->second.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        if ( is_ldr() )
        {
          PBYTE data = (PBYTE)iter->second.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( NULL == data || !m_pe->is_inside(data) )
            continue;
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
            PBYTE data = (PBYTE)iter->second.get(AD_REG_X0);
            if ( data == NULL || !m_pe->is_inside(data) )
              continue;
            // check size
            if ( 0x60 != *(PDWORD)data )
              continue;
            try
            {
              GUID *tmp_guid = (GUID *)(data + 4);
              auto pair = std::make_pair(*tmp_guid, data);
              m_out_res.push_back(pair);
              res++;
            } catch(std::bad_alloc)
            { return res; }
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
