#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::zero_data()
{
  // fill auxilary data
  aux_KeAcquireSpinLockRaiseToDpc = NULL;
  aux_ExAcquirePushLockExclusiveEx = NULL;
  aux_ObReferenceObjectByHandle = NULL;
  aux_KfRaiseIrql = NULL;
  aux_memset = NULL;
  if ( m_ed != NULL )
  {
    const export_item *exp = m_ed->find("KeAcquireSpinLockRaiseToDpc");
    if ( exp != NULL )
      aux_KeAcquireSpinLockRaiseToDpc = m_pe->base_addr() + exp->rva;
    exp = m_ed->find("ExAcquirePushLockExclusiveEx");
    if ( exp != NULL )
      aux_ExAcquirePushLockExclusiveEx = m_pe->base_addr() + exp->rva;
    exp = m_ed->find("ObReferenceObjectByHandle");
    if ( exp != NULL )
      aux_ObReferenceObjectByHandle = m_pe->base_addr() + exp->rva;
    exp = m_ed->find("KfRaiseIrql");
    if ( exp != NULL )
      aux_KfRaiseIrql = m_pe->base_addr() + exp->rva;
    exp = m_ed->find("memset");
    if ( exp != NULL )
      aux_memset = m_pe->base_addr() + exp->rva;
  }
  // zero output data
  m_ExNPagedLookasideLock = NULL;
  m_ExNPagedLookasideListHead = NULL;
  m_ExPagedLookasideLock = NULL;
  m_ExPagedLookasideListHead = NULL;
  m_KiDynamicTraceEnabled = m_KiTpStateLock = m_KiTpHashTable = NULL;
  m_stack_base_off = m_stack_limit_off = m_thread_id_off = m_thread_process_off = 0;
  m_KeLoaderBlock = m_KiServiceLimit = m_KiServiceTable = NULL;
  m_ObHeaderCookie = m_ObTypeIndexTable = m_ObpSymbolicLinkObjectType = NULL;
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
  if ( m_KeLoaderBlock != NULL )
    printf("KeLoaderBlock: %p\n", m_KeLoaderBlock - mz);
  if ( m_KiServiceLimit != NULL )
    printf("KiServiceLimit: %p\n", m_KiServiceLimit - mz);
  if ( m_KiServiceTable != NULL )
    printf("KiServiceTable: %p\n", m_KiServiceTable - mz);
  if ( m_ObHeaderCookie != NULL )
    printf("ObHeaderCookie: %p\n", m_ObHeaderCookie - mz);
  if ( m_ObTypeIndexTable != NULL )
    printf("ObTypeIndexTable: %p\n", m_ObTypeIndexTable - mz);
  if ( m_ObpSymbolicLinkObjectType != NULL ) 
    printf("ObpSymbolicLinkObjectType: %p\n", m_ObpSymbolicLinkObjectType - mz);
  if ( m_stack_base_off )
    printf("KTHREAD.StackBase offset:  %X\n", m_stack_base_off);
  if ( m_stack_limit_off )
    printf("KTHREAD.StackLimit offset: %X\n", m_stack_limit_off);
  if ( m_thread_id_off )
    printf("ETHREAD.ThreadId offset:   %X\n", m_thread_id_off);
  if ( m_thread_process_off )
    printf("KTHREAD.Process offset:    %X\n", m_thread_process_off);
}

int ntoskrnl_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("ExInitializePagedLookasideList");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += find_lock_list(next, m_ExPagedLookasideLock, m_ExPagedLookasideListHead);
  }
  exp = m_ed->find("ExInitializeNPagedLookasideList");
  if ( exp != NULL ) 
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += find_lock_list(next, m_ExNPagedLookasideLock, m_ExNPagedLookasideListHead);
  }
  exp = m_ed->find("KeSetTracepoint");
  if ( exp != NULL ) 
   try
   {
     res += hack_tracepoints(mz + exp->rva);
   } catch(std::bad_alloc)
   { }
  DWORD ep = m_pe->entry_point();
  if ( ep )
   try
   {
     res += hack_entry(mz + ep);
   } catch(std::bad_alloc)
   { }
  if ( m_KiServiceTable != NULL )
  {
    PBYTE addr = NULL;
    if ( get_nt_addr("ZwQuerySymbolicLinkObject", addr) )
      res += hack_obref_type(addr, m_ObpSymbolicLinkObjectType);
  }
  exp = m_ed->find("ObReferenceObjectByPointerWithTag");
    res += hack_ob_types(mz + exp->rva);
  if ( exp != NULL ) 
  // thread offsets
  exp = m_ed->find("PsGetCurrentThreadId");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_id_off);
  exp = m_ed->find("PsGetCurrentThreadStackLimit");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_stack_limit_off);
  exp = m_ed->find("PsGetCurrentThreadStackBase");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_stack_base_off);
  exp = m_ed->find("PsGetCurrentThreadProcess");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_process_off);
  return res;
}

int ntoskrnl_hack::get_nt_addr(const char *name, PBYTE &addr)
{
  if ( m_KiServiceTable == NULL )
    return 0;
  const export_item *exp = m_ed->find(name);
  if ( NULL == exp )
    return 0;
  DWORD idx = 0;
  PBYTE mz = m_pe->base_addr();
  if ( !hack_x16(mz + exp->rva, idx) )
    return 0;
  addr = mz + *((PDWORD)m_KiServiceTable + idx);
  return 1;
}

int ntoskrnl_hack::hack_x16(PBYTE psp, DWORD &off)
{
  if ( !setup(psp) )
    return 0;
  int reg = -1;
  off = 0;
  for ( DWORD i = 0; i < 4; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_mov_rimm() && get_reg(0) == AD_REG_X16 )
    {
      off = (DWORD)m_dis.operands[1].op_imm.bits;
      break;
    }
  }
  return (off != 0);
}

// according to https://docs.microsoft.com/ru-ru/cpp/build/arm64-windows-abi-conventions?view=vs-2019
// x18 reg points to KPCR in kernel mode (and in user mode, points to TEB)
int ntoskrnl_hack::hack_x18(PBYTE psp, DWORD &off)
{
  if ( !setup(psp) )
    return 0;
  int reg = -1;
  off = 0;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_ldr() && get_reg(1) == AD_REG_X18 )
      reg = get_reg(0);
    if ( is_ldr() && reg == get_reg(1) )
    {
      off = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
    if ( is_add() && reg == get_reg(1) )
    {
      off = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
  }
  return (off != 0);
}

int ntoskrnl_hack::find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list)
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
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
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

int ntoskrnl_hack::hack_obref_type(PBYTE psp, PBYTE &off)
{
  if ( !setup(psp) )
    return 0;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  off = NULL;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("hack_obref_type: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( DWORD i = 0; i < 100; i++ )
      {
        if ( !disasm() || is_ret() )
          return 0;
        if ( check_jmps(cgraph) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
        }
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
           if ( caddr == aux_ObReferenceObjectByHandle )
           {
             off = (PBYTE)used_regs.get(AD_REG_X2);
             goto end;
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
  return (off != NULL);

}

int ntoskrnl_hack::hack_ob_types(PBYTE psp)
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
    // ldrb for cookie
    if ( !state && is_ldrb() ) 
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, "ALMOSTRO") )
         used_regs.zero(get_reg(0));
       else {
         m_ObHeaderCookie = what;
         state = 1;
       }
    }
    // add for index tab
    if ( state && is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, "ALMOSTRO") )
         used_regs.zero(get_reg(0));
       else {
         m_ObTypeIndexTable = what;
         break;
       }
    }
  }
  return (m_ObHeaderCookie != NULL) && (m_ObTypeIndexTable != NULL);
}

int ntoskrnl_hack::hack_sdt(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("hack_sdt: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( DWORD i = 0; i < 100; i++ )
      {
        if ( !disasm() || is_ret() )
          return 0;
        if ( check_jmps(cgraph) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr);
          break;
        }
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".rdata") )
            used_regs.zero(get_reg(0));
        }
        if ( is_ldr() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".rdata") )
            used_regs.zero(get_reg(0));
        }
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
          if ( used_regs.get(AD_REG_X2) != NULL &&
               used_regs.get(AD_REG_X0) != NULL
             )
          {
            m_KiServiceLimit = (PBYTE)used_regs.get(AD_REG_X2);
            m_KiServiceTable = (PBYTE)used_regs.get(AD_REG_X0);
            goto end;
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
  return (m_KiServiceLimit != NULL) && (m_KiServiceTable);
}

int ntoskrnl_hack::hack_entry(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_n = 0;
  int edge_gen = 0;
  PBYTE KiInitializeKernel = NULL;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("hack_entry: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( ; ; )
      {
        // state 0 - at start function
        //       1 - after memset, can grab KeLoaderBlock
        //       2 - after call reg, next call will be KiInitializeKernel
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
        // check for call
        if ( is_bl_jimm(b_addr) )
        {
          if ( b_addr == aux_memset )
            state = 1;
          else if ( b_addr == aux_KfRaiseIrql )
            state = 2;
          else if ( 2 == state )
          {
            KiInitializeKernel = b_addr;
            goto end;
          }
        }
        if ( is_bl_reg() )
          state = 2;
        if ( (m_KeLoaderBlock == NULL) && (1 == state) && is_adrp(used_regs) )
          continue;
        if ( (m_KeLoaderBlock == NULL) && (1 == state) && is_str() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( in_section(what, "ALMOSTRO") )          
            m_KeLoaderBlock = what;
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
  if ( KiInitializeKernel == NULL )
    return 0;
  return hack_sdt(KiInitializeKernel);
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
