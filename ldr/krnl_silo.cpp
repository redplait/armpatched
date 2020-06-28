#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

int ntoskrnl_hack::hack_start_silo(PBYTE psp)
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
      int state = iter->second;
      if ( m_verbose )
        printf("hack_start_silo: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
          {
             used_regs.zero(get_reg(0));
             continue;
          }
          if ( state )
          {
            if ( what != aux_PsInitialSystemProcess )
            {
              m_PspSiloMonitorList = what;
              goto end;
            }
          }
        }
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( !state && (addr == aux_ExAcquirePushLockExclusiveEx) )
          {
             m_PspSiloMonitorLock = (PBYTE)used_regs.get(AD_REG_X0);
             state = 1;
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
  return (m_PspSiloMonitorLock != NULL) && (m_PspSiloMonitorList != NULL);
}