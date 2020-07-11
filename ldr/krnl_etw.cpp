#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

int ntoskrnl_hack::hack_CmpTraceRoutine(PBYTE psp)
{
  statefull_graph<PBYTE, PBYTE> cgraph;
  std::list<std::pair<PBYTE, PBYTE> > addr_list;
  auto curr = std::make_pair(psp, (PBYTE)NULL);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      PBYTE candidate = iter->second;
      int state = (candidate == NULL) ? 0 : 1;
      if ( m_verbose )
        printf("hack_CmpTraceRoutine: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, candidate) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        // ldr
        if ( !state && is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, "PAGEDATA") )
            used_regs.zero(get_reg(0));
          else
          {
            candidate = what;
            state = (candidate == NULL) ? 0 : 1;
          }
          continue;
        }
        // br
        if ( state && is_br_reg() )
        {
          PBYTE what = (PBYTE)used_regs.get(get_reg(0));
          if ( what != NULL && in_section(what, "PAGE") )
          {
             cgraph.add(what, candidate);
             continue;
          }
        }
        // mov reg, imm
        if ( state && is_mov_rimm() )
        {
          if ( 0x20000 == (DWORD)m_dis.operands[1].op_imm.bits )
          {
             m_CmpTraceRoutine = candidate;
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
  return (m_CmpTraceRoutine != NULL);
}