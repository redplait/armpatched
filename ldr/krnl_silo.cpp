#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_silo()
{
  m_PspSiloMonitorLock = m_PspSiloMonitorList = m_PspHostSiloGlobals = NULL;
}

void ntoskrnl_hack::dump_silo(PBYTE mz) const
{
  if ( m_PspSiloMonitorLock != NULL )
    printf("PspSiloMonitorLock: %p\n", PVOID(m_PspSiloMonitorLock - mz));
  if ( m_PspSiloMonitorList != NULL )
    printf("PspSiloMonitorList: %p\n", PVOID(m_PspSiloMonitorList - mz));
  if ( m_PspHostSiloGlobals != NULL )
    printf("PspHostSiloGlobals: %p\n", PVOID(m_PspHostSiloGlobals - mz));
}

int ntoskrnl_hack::disasm_PsGetCurrentServerSiloGlobals(PBYTE psp)
{
  PBYTE last_cnz = NULL;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while (edge_gen < 100)
  {
    for (auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter)
    {
      psp = *iter;
      if (m_verbose)
        printf("disasm_PsGetCurrentServerSiloGlobals: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      edge_n++;
      regs_pad used_regs;
      for (DWORD i = 0; i < 100; i++)
      {
        if (!disasm() || is_ret())
          break;
        // check cbnz
        PBYTE addr = NULL;
        if ( is_cbnz_jimm(addr) )
          last_cnz = addr;
        // and only then add edges in graph
        if ( check_jmps(cgraph) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( what == m_PspHostSiloGlobals )
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
  if ( last_cnz == NULL )
    return 0;
#ifdef _DEBUG
  printf("last_cbnz: %p\n", last_cnz);
#endif /* _DEBUG */
  return find_ejob_siloglobals(last_cnz);
}

// disasm branch in PsGetCurrentServerSiloGlobals where EJOB is not null
int ntoskrnl_hack::find_ejob_siloglobals(PBYTE psp)
{
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while (edge_gen < 100)
  {
    for (auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter)
    {
      psp = *iter;
      if (m_verbose)
        printf("find_ejob_siloglobals: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      edge_n++;
      regs_pad used_regs;
      for (DWORD i = 0; i < 100; i++)
      {
        if (!disasm() || is_ret())
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
          if ( what != NULL && in_executable_section(what) )
             cgraph.add(what);
          break;
        }
        // ldr
        if ( is_ldr() && get_reg(0) == AD_REG_X0 )
        {
          m_ejob_silo_globals_offset = (DWORD)m_dis.operands[2].op_imm.bits;
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
  return (m_ejob_silo_globals_offset != 0);
}

int ntoskrnl_hack::hack_silo_global(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( in_section(what, "CACHEALI") )
       {
         m_PspHostSiloGlobals = what;
         break;
       }
    }
  }
  return (m_PspHostSiloGlobals != NULL);
}

int ntoskrnl_hack::hack_start_silo(PBYTE psp)
{
  traverse_simple_state_graph(psp, [&](int *state, regs_pad *used_regs) -> int
   {
      if ( is_add() )
      {
        PBYTE what = (PBYTE)used_regs->add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
        if ( !in_section(what, ".data") )
        {
           used_regs->zero(get_reg(0));
           return 0;
        }
        if ( *state )
        {
          if ( what != aux_PsInitialSystemProcess )
          {
             m_PspSiloMonitorList = what;
             return 1;
          }
        }
      }
      PBYTE addr = NULL;
      if ( is_bl_jimm(addr) )
      {
        if ( !*state && (addr == aux_ExAcquirePushLockExclusiveEx) )
        {
           m_PspSiloMonitorLock = (PBYTE)used_regs->get(AD_REG_X0);
           *state = 1;
        }
      }
      return 0;
   }, "hack_start_silo");

  return (m_PspSiloMonitorLock != NULL) && (m_PspSiloMonitorList != NULL);
}