#include "stdafx.h"
#include "krnl_hack.h"
#include "bm_search.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_dbg_data()
{
  m_DbgkDebugObjectType = m_RtlpDebugPrintCallbackLock = m_RtlpDebugPrintCallbackList = NULL;
  m_DebugPrintCallback_size = m_KdComponentTable_size = 0;
  m_KdComponentTable = m_Kd_WIN2000_Mask = NULL;
}

void ntoskrnl_hack::dump_dbg_data(PBYTE mz) const
{
  if ( m_DbgkDebugObjectType != NULL )
    printf("DbgkDebugObjectType: %p\n", PVOID(m_DbgkDebugObjectType - mz));
  if ( m_RtlpDebugPrintCallbackLock != NULL )
    printf("RtlpDebugPrintCallbackLock: %p\n", PVOID(m_RtlpDebugPrintCallbackLock - mz));
  if ( m_RtlpDebugPrintCallbackList != NULL )
    printf("RtlpDebugPrintCallbackList: %p\n", PVOID(m_RtlpDebugPrintCallbackList - mz));
  if ( m_DebugPrintCallback_size )
    printf("DebugPrintCallback size: %X\n", m_DebugPrintCallback_size);
  if ( m_KdComponentTable != NULL )
    printf("KdComponentTable: %p, size %X\n", PVOID(m_KdComponentTable - mz), m_KdComponentTable_size);
  if ( m_Kd_WIN2000_Mask != NULL )
    printf("Kd_WIN2000_Mask: %p\n", PVOID(m_Kd_WIN2000_Mask - mz));
}

int ntoskrnl_hack::hack_kd_masks(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for cmp r0, imm
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( !state && is_cmp_rimm() && get_reg(0) == AD_REG_X0 )
    {
      m_KdComponentTable_size = (DWORD)m_dis.operands[1].op_imm.bits;
      state = 1;
    }
    if ( is_adrp(used_regs) )
      continue;
    // ldr - Kd_WIN2000_Mask
    if ( state && is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else
        m_Kd_WIN2000_Mask = what;
    }
    // add
    if ( state && is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else
      {
        m_KdComponentTable = what;
        break;
      }
    }
  }
  return (m_KdComponentTable != NULL) && (m_Kd_WIN2000_Mask != NULL);
}

int ntoskrnl_hack::find_DbgpInsertDebugPrintCallback_by_sign(PBYTE mz)
{
  // try search tag in .text section
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
  const DWORD sign = 0x62436244;
  bm_search srch((const PBYTE)&sign, sizeof(sign));
  PBYTE curr = start;
  std::list<PBYTE> founds;
  while ( curr < end )
  {
    const PBYTE fres = srch.search(curr, end - curr);
    if ( NULL == fres )
      break;
    try
    {
      founds.push_back(fres);
    } catch(std::bad_alloc)
    { return 0; }
    curr = fres + sizeof(sign);
  }
  if ( founds.empty() )
    return 0;
  for ( auto citer = founds.cbegin(); citer != founds.cend(); ++citer )
  {
    PBYTE func = find_pdata(*citer);
    if ( NULL == func )
      continue;
#ifdef _DEBUG
    printf("find_DbgpInsertDebugPrintCallback_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( hack_DbgpInsertDebugPrintCallback(func) )
      return 1;
  }
  return 0;
}

int ntoskrnl_hack::hack_DbgpInsertDebugPrintCallback(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second; // 0 - wait for ExAllocatePoolWithTag
                                // 1 - ExAcquireSpinLockExclusiveAtDpcLevel
      if ( m_verbose )
        printf("hack_DbgpInsertDebugPrintCallback: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( is_mov_rimm() )
        {
          used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
          continue;
        }
        if ( state && is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
          {
            used_regs.zero(get_reg(0));
            continue;
          }
          if ( 2 == state )
          {
            m_RtlpDebugPrintCallbackList = what;
            goto end;
          }
          continue;
        }
        // call
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAllocatePoolWithTag )
          {
            m_DebugPrintCallback_size = (DWORD)used_regs.get(AD_REG_X1);
            state = 1;
            continue;
          }
          if ( addr == aux_ExAcquireSpinLockExclusiveAtDpcLevel )
          {
            m_RtlpDebugPrintCallbackLock = (PBYTE)used_regs.get(AD_REG_X0);
            state = 2;
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
  return (m_RtlpDebugPrintCallbackLock != NULL) && (m_RtlpDebugPrintCallbackList != NULL);
}