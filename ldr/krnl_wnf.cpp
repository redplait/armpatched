#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_wnf()
{
  m_ExpWnfProcessesListLock = m_ExpWnfProcessesListHead = NULL;
  m_wnf_proc_ctx_size = 0;
}

void ntoskrnl_hack::dump_wnf(PBYTE mz) const
{
  if ( m_ExpWnfProcessesListLock != NULL )
    printf("ExpWnfProcessesListLock: %p\n", PVOID(m_ExpWnfProcessesListLock - mz));
  if ( m_ExpWnfProcessesListHead != NULL )
    printf("ExpWnfProcessesListHead: %p\n", PVOID(m_ExpWnfProcessesListHead - mz));
  if ( m_wnf_proc_ctx_size )
    printf("sizeof(WNF_PROCESS_CONTEXT): %X\n", m_wnf_proc_ctx_size);
}

// try to find ExpWnfCreateProcessContext from NtSetWnfProcessNotificationEvent
int ntoskrnl_hack::try_wnf_proc_ctx(PBYTE psp, PBYTE mz)
{
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  PBYTE create_ctx = NULL;
  while (edge_gen < 100)
  {
    for (auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter)
    {
      psp = *iter;
      if (m_verbose)
        printf("try_wnf_proc_ctx: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      edge_n++;
      regs_pad used_regs;
      for (DWORD i = 0; i < 100; i++)
      {
        if ( !disasm() || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        // br
        if ( is_br_reg() )
        {
          PBYTE what = (PBYTE)used_regs.get(get_reg(0));
          if ( what != NULL && in_section(what, "PAGE") )
             cgraph.add(what);
          break;
        }
        // call
        PBYTE b_addr = NULL;
        if ( is_bl_jimm(b_addr) )
        {
          if ( b_addr == aux_ObReferenceObjectByHandle )
            break;
          if ( b_addr == aux_ExFreePoolWithTag )
            continue;
          create_ctx = b_addr;
          goto end;
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
  if ( create_ctx == NULL )
    return 0;
#ifdef _DEBUG
  printf("ExpWnfCreateProcessContext: %p\n", PVOID(create_ctx - mz));
#endif /* _DEBUG */
  return disasm_ExpWnfCreateProcessContext(create_ctx, mz);
}

int ntoskrnl_hack::disasm_ExpWnfCreateProcessContext(PBYTE psp, PBYTE mz)
{
  // state - 0 - wait for ExAllocatePoolWithTag
  //         1 - wait for DMB opcode
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
      int state = iter->second;
      if ( m_verbose )
        printf("disasm_ExpWnfCreateProcessContext: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      DWORD last_x1 = 0; // allocation size
      PBYTE last_data = NULL;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( !state && is_mov_rimm() && get_reg(0) == AD_REG_X1 )
          last_x1 = (DWORD)m_dis.operands[1].op_imm.bits;
        // call
        PBYTE b_addr = NULL;
        if ( is_bl_jimm(b_addr) )
        {
          if ( b_addr == aux_ExAllocatePoolWithTag )
          {
            state = 1;
            m_wnf_proc_ctx_size = last_x1;
          }
        }
        if ( state && is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( in_section(what, "PAGEDATA") )
          {
            last_data = what;
            if ( (m_ExpWnfProcessesListHead == NULL) && (m_ExpWnfProcessesListLock != NULL) && what != m_ExpWnfProcessesListLock )
            {
               m_ExpWnfProcessesListHead = what;
               goto end;
            }
          }
        }
        // check for DMB opcode
        if ( state && m_dis.instr_id == AD_INSTR_DMB )
        {
          m_ExpWnfProcessesListLock = last_data;
          state++;
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
  return (m_ExpWnfProcessesListLock != NULL) && (m_ExpWnfProcessesListHead != NULL);
}