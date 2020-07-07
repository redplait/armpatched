#include "stdafx.h"
#include "ntdll_hack.h"
#include "cf_graph.h"

void ntdll_hack::zero_data()
{
  // fill auxilary data
  init_aux("RtlAcquireSRWLockExclusive", aux_RtlAcquireSRWLockExclusive);
  init_aux("RtlAllocateHeap", aux_RtlAllocateHeap);
  aux_LdrpMrdataLock = NULL;
  // zero output data
  m_LdrpVectorHandlerList = NULL;
  m_LdrpDllDirectoryLock = m_LdrpUserDllDirectories = NULL;
}

void ntdll_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_LdrpVectorHandlerList != NULL )
    printf("LdrpVectorHandlerList: %p\n", PVOID(m_LdrpVectorHandlerList - mz));
  if ( m_LdrpDllDirectoryLock != NULL )
    printf("LdrpDllDirectoryLock: %p\n", PVOID(m_LdrpDllDirectoryLock - mz));
  if ( m_LdrpUserDllDirectories != NULL )
    printf("LdrpUserDllDirectories: %p\n", PVOID(m_LdrpUserDllDirectories - mz));
}

int ntdll_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("RtlAddVectoredExceptionHandler");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )      
      res += hack_veh(next);
    else
      res += hack_veh(mz + exp->rva);
  }
  exp = m_ed->find("LdrAddDllDirectory");
  if ( exp != NULL )
    res += hack_add_dll_dirs(mz + exp->rva);

  return res;
}

// state 0 - wait for RtlAcquireSRWLockExclusive to find LdrpDllDirectoryLock
int ntdll_hack::hack_add_dll_dirs(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_n = 0;
  int edge_gen = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("hack_add_dll_dirs: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        // adrp/adr pair
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
          if ( 1 == state )
          {
            m_LdrpUserDllDirectories = what;
            goto end;
          }
          continue;
        }
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
           if ( !state && caddr == aux_RtlAcquireSRWLockExclusive )
           {
             m_LdrpDllDirectoryLock = (PBYTE)used_regs.get(AD_REG_X0);
             state = 1;
             continue;
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
end:
  return (m_LdrpUserDllDirectories != NULL);
}

// state 0 - wait for RtlAcquireSRWLockExclusive to find LdrpMrdataLock
//       1 - wait for RtlAllocateHeap
int ntdll_hack::hack_veh(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_n = 0;
  int edge_gen = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("hack_veh: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        // adrp/adr pair
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") && !in_section(what, ".mrdata") )
            used_regs.zero(get_reg(0));
          if ( 2 == state )
          {
            m_LdrpVectorHandlerList = what;
            goto end;
          }
          continue;
        }
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
           if ( !state && caddr == aux_RtlAcquireSRWLockExclusive )
           {
             aux_LdrpMrdataLock = (PBYTE)used_regs.get(AD_REG_X0);
             state = 1;
             continue;
           }
           if ( caddr == aux_RtlAllocateHeap )
             state = 2;
        }
      }
      cgraph.add_range(psp, m_psp - psp);
    }
    // prepare for next edge generation
    edge_gen++;
    if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
      break;    
  }
end:
  return (m_LdrpVectorHandlerList != NULL);
}