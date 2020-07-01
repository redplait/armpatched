#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

DWORD tp_hash(const char *name)
{
  if ( !name[0] || !name[1] )
    return 0;
  DWORD res = 0;
  for ( name += 2; *name; name++ )
  {
    res = (1025 * (res + *name) >> 6) ^ (1025 * (res + *name));
  }
  return res;
}

int ntoskrnl_hack::find_stab_types(PBYTE mz)
{
  int res = 0;
  DWORD val = tp_hash("NtOpenKeyTransactedEx");
  std::map<DWORD, PBYTE>::const_iterator c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_CmRegistryTransactionType, ".data");
  val = tp_hash("NtWaitForKeyedEvent");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_ExpKeyedEventObjectType, "ALMOSTRO");
  val = tp_hash("NtWaitForWorkViaWorkerFactory");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_ExpWorkerFactoryObjectType, "ALMOSTRO");
  val = tp_hash("NtCancelWaitCompletionPacket");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_IopWaitCompletionPacketObjectType, "ALMOSTRO");
  val = tp_hash("NtDeletePrivateNamespace");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_ObpDirectoryObjectType, ".data");
  val = tp_hash("NtStartProfile");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_ExProfileObjectType, "ALMOSTRO");
  val = tp_hash("NtTraceEvent");
  c = m_stab.find(val);
  if ( c != m_stab.end() )
    res += hack_obref_type(c->second, m_EtwpRegistrationObjectType, "ALMOSTRO");
  return res;
}

struct tp_sdt
{
  DWORD hash;
  DWORD unk;
  uint64 addr;
};

int ntoskrnl_hack::find_trace_sdt(PBYTE mz)
{
  DWORD val = tp_hash("NtCreateSymbolicLinkObject");
  const one_section *page = m_pe->find_section_by_name("PAGE");
  if ( NULL == page )
    return 0;
  PBYTE curr = mz + page->va;
  PBYTE end = curr + page->size;
  bm_search srch((const PBYTE)&val, sizeof(val));
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
    curr = fres + sizeof(val);
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  // ok, we found something in middle of tab
  // try to find lower bound
  curr = mz + page->va;
  tp_sdt *lower = (tp_sdt *)*(founds.cbegin());
  for ( lower-- ; lower >= (tp_sdt *)curr; lower-- )
  {
    const one_section *s = m_pe->find_section_rva((PBYTE)lower->addr - mz);
    if ( s == NULL )
    {
      lower += 1;
      break;
    }
    if ( ! (s->flags & IMAGE_SCN_MEM_EXECUTE) )
    {
      lower += 1;
      break;
    }    
  }
  // fill m_stab
  aux_tp_stab = (PBYTE)lower;
  for ( ; lower < (tp_sdt *)end; ++lower )
  {
    const one_section *s = m_pe->find_section_rva((PBYTE)lower->addr - mz);
    if ( s == NULL )
      break;
    if ( ! (s->flags & IMAGE_SCN_MEM_EXECUTE) )
      break;
    try
    {
       m_stab[lower->hash] = (PBYTE)lower->addr;
    } catch(std::bad_alloc)
    { break; }
  }
  if ( !m_stab.empty() )
  {
    // try KiSystemServiceTraceCallbackTable - from KiGetSystemServiceTraceTable
    try_KiGetSystemServiceTraceTable_by_sign(mz);
  }
  return m_stab.empty() ? 0 : 1;
}

int ntoskrnl_hack::try_KiGetSystemServiceTraceTable_by_sign(PBYTE mz)
{
  // try search in PAGE section
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
  const DWORD sign = 0x7454694B;
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
    printf("try_KiGetSystemServiceTraceTable_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( hack_KiSystemServiceTraceCallbackTable(mz, func) )
      return 1;
  }
  return 0;
}

int ntoskrnl_hack::hack_KiSystemServiceTraceCallbackTable(PBYTE mz, PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  int state = 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 30; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_ldr() ) 
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, "PAGEDATA") )
         used_regs.zero(get_reg(0));
       else {
         m_KiSystemServiceTraceCallbackTable = what;
         state = 1;
       }
       continue;
    }
    if ( is_mov_rimm() )
    {
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      continue;
    }
    PBYTE b_addr = NULL;
    if ( is_bl_jimm(b_addr) )
    {
      if ( state && (b_addr == aux_ExAllocatePoolWithTag) )
      {
        m_KiSystemServiceTraceCallbackTable_size = (DWORD)used_regs.get(AD_REG_X1);
        break;
      }
    }
  }
  return (m_KiSystemServiceTraceCallbackTable != NULL);
}

int ntoskrnl_hack::hack_tracepoints(PBYTE psp)
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
        printf("hack_tracepoints: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr, state);
          break;
        }
        // adrp/adr pair
        if ( is_adrp(used_regs) )
          continue;
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
