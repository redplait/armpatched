#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::zero_data()
{
  // fill auxilary data
  aux_KeAcquireSpinLockRaiseToDpc = NULL;
  aux_ExAcquirePushLockExclusiveEx = NULL;
  if ( m_ed != NULL )
  {
    const export_item *exp = m_ed->find("KeAcquireSpinLockRaiseToDpc");
    if ( exp != NULL )
      aux_KeAcquireSpinLockRaiseToDpc = m_pe->base_addr() + exp->rva;
    exp = m_ed->find("ExAcquirePushLockExclusiveEx");
    if ( exp != NULL )
      aux_ExAcquirePushLockExclusiveEx = m_pe->base_addr() + exp->rva;
  }
  // zero output data
  m_ExNPagedLookasideLock = NULL;
  m_ExNPagedLookasideListHead = NULL;
  m_ExPagedLookasideLock = NULL;
  m_ExPagedLookasideListHead = NULL;
  m_KiDynamicTraceEnabled = m_KiTpStateLock = m_KiTpHashTable = NULL;
}

void ntoskrnl_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_ExNPagedLookasideLock != NULL )
    printf("ExNPagedLookasideLock: %p\n", m_ExNPagedLookasideLock - mz);
  if ( m_ExNPagedLookasideListHead != NULL )
    printf("ExNPagedLookasideListHead: %p\n", m_ExNPagedLookasideListHead - mz);
  if ( m_ExPagedLookasideLock != NULL )
    printf("ExPagedLookasideLock: %p\n", m_ExPagedLookasideLock - mz);
  if ( m_ExPagedLookasideListHead != NULL )
    printf("ExPagedLookasideListHead: %p\n", m_ExPagedLookasideListHead - mz);
  if ( m_KiDynamicTraceEnabled != NULL ) 
    printf("KiDynamicTraceEnabled: %p\n", m_KiDynamicTraceEnabled - mz);
  if ( m_KiTpStateLock != NULL )
    printf("KiTpStateLock: %p\n", m_KiTpStateLock - mz);
  if ( m_KiTpHashTable != NULL )
    printf("KiTpHashTable: %p\n", m_KiTpHashTable - mz);
}

int ntoskrnl_hack::hack(int verbose)
{
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("ExInitializePagedLookasideList");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next, verbose) )
      res += find_lock_list(next, m_ExPagedLookasideLock, m_ExPagedLookasideListHead, verbose);
  }
  exp = m_ed->find("ExInitializeNPagedLookasideList");
  if ( exp != NULL ) 
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next, verbose) )
      res += find_lock_list(next, m_ExNPagedLookasideLock, m_ExNPagedLookasideListHead, verbose);
  }
  exp = m_ed->find("KeSetTracepoint");
  if ( exp != NULL ) 
   try
   {
     res += hack_tracepoints(mz + exp->rva, verbose);
   } catch(std::bad_alloc)
   { }
  return res;
}

int ntoskrnl_hack::find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list, int verbose)
{
  lock = NULL;
  list = NULL;
  if ( !setup(psp) )
    return 0;
  int state = 0; // 1 - we got lock
  regs_pad used_regs;
  PBYTE tmp;
  for ( DWORD i = 0; i < 200; i++ )
  {
    if ( !disasm(verbose) || is_ret() )
      return 0;
    if ( is_adrp() )
    {
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      continue;
    }
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else if ( state )
      {
        list = what;
        break;
      }
    }
    // check for call
    if ( is_bl_jimm(tmp) )
    {
      if ( tmp == aux_KeAcquireSpinLockRaiseToDpc )
      {
        state = 1;
        lock = (PBYTE)used_regs.get(AD_REG_X0);
      }
    }
  }
  return (lock != NULL) && (list != NULL);
}

int ntoskrnl_hack::hack_tracepoints(PBYTE psp, int verbose)
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
      if ( verbose )
        printf("hack_tracepoints: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      regs_pad used_regs;
      if ( !setup(psp) )
        continue;
      edge_n++;
      for ( ; ; )
      {
        if ( !disasm(verbose, state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr, state);
          break;
        }
        // adrp/adr pair
        if ( is_adrp() )
        {
          used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
          continue;
        }
        if ( is_ldr() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( in_section(what, "ALMOSTRO") )
          {
            if ( !state )
            {
              m_KiDynamicTraceEnabled = what;
              state = 1;
              continue;
            }
          } else if ( in_section(what, ".data") )
          {
            if ( 2 == state )
            {
              m_KiTpHashTable = what;
              goto end;
            }
          }
        } else
          used_regs.zero(get_reg(0));
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
        }
        // check for call
        if ( is_bl_jimm(b_addr) )
        {
           if (b_addr == aux_ExAcquirePushLockExclusiveEx )
           {
             state = 2;
             m_KiTpStateLock = (PBYTE)used_regs.get(AD_REG_X0);
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
  return (m_KiTpStateLock != NULL) && (m_KiTpHashTable != NULL);
}