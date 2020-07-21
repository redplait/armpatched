#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_etw()
{
  m_CmpTraceRoutine = NULL;
  m_EtwpSessionDemuxObjectType = NULL;
}

void ntoskrnl_hack::dump_etw(PBYTE mz) const
{
  if ( m_CmpTraceRoutine != NULL )
    printf("CmpTraceRoutine: %p\n", PVOID(m_CmpTraceRoutine - mz));
  if ( m_EtwpSessionDemuxObjectType != NULL )
    printf("EtwpSessionDemuxObjectType: %p\n", PVOID(m_EtwpSessionDemuxObjectType - mz));
}

int ntoskrnl_hack::find_EtwpSessionDemuxObjectType(PBYTE mz)
{
  static const wchar_t *name = L"EtwSessionDemuxEntry";
  // find string in PAGE section
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  size_t b_size = sizeof(wchar_t) * wcslen(name);
  bm_search srch((const PBYTE)name, b_size);
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
  // ok, now find reference in PAGE section
  PBYTE addr = *(founds.cbegin());
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, addr);
  if ( res == NULL )
    return 0;
  return hack_EtwpSessionDemuxObjectType(res);
}

int ntoskrnl_hack::hack_EtwpSessionDemuxObjectType(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 40; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "ALMOSTRO") )
        used_regs.zero(get_reg(0));
      continue;
    }
    // call ObCreateObjectTypeEx
    PBYTE addr = NULL;
    if ( is_bl_jimm(addr) )
    {
      if ( addr == aux_ObCreateObjectTypeEx )
      {
        m_EtwpSessionDemuxObjectType = (PBYTE)used_regs.get(AD_REG_X4);
        break;
      }
    }
  }
  return (m_EtwpSessionDemuxObjectType != NULL);
}

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