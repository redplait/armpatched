#include "stdafx.h"
#include "krnl_hack.h"
#include "bm_search.h"
#include "cf_graph.h"

int ntoskrnl_hack::find_crash_tab(PBYTE mz)
{
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  const wchar_t *crash_name = L"\\SystemRoot\\System32\\Drivers\\crashdmp.sys";
  size_t b_size = sizeof(wchar_t) * wcslen(crash_name);
  bm_search srch((const PBYTE)crash_name, b_size);
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
    curr = fres + b_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  PBYTE addr = *(founds.cbegin());
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, addr);
  if ( res == NULL )
    return 0;
  if ( m_verbose )
    printf("find_crash_tab: %p %X disasms %X adrp %X add\n", (PBYTE)(res - mz), xf.disasm_cnt, xf.adrp_cnt, xf.add_cnt);
  return disasm_crash_tab(res);
}

int ntoskrnl_hack::disasm_crash_tab(PBYTE psp)
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
        printf("disasm_crash_tab: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        if ( state && is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
          continue;
        }
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_RtlImageNtHeader )
          {
            state = 1;
            continue;
          }
          if ( state && (addr == aux_dispatch_icall) )
          {
            m_CrashdmpCallTable = (PBYTE)used_regs.get(AD_REG_X1);
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
  return (m_CrashdmpCallTable != NULL);
}