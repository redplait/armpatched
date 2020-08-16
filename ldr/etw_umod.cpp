#include "stdafx.h"
#include "hack.h"
#include "bm_search.h"
#include "cf_graph.h"

static const int guid_size = 16;

int arm64_hack::find_simple_guid(const PBYTE guid, PBYTE mz, PBYTE &out_res)
{
  PBYTE aux = NULL;
  find_etw_guid((const PBYTE)guid, mz, aux);
  if ( aux == NULL )
    return 0;
  return resolve_etw(aux, mz, out_res);
}

int arm64_hack::resolve_etw(PBYTE what, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, what);
  if ( res == NULL )
    return 0;
  PBYTE func = find_pdata(res);
  if ( NULL == func )
    return 0;
  return disasm_etw(func, what, out_res);
}

int arm64_hack::disasm_etw(PBYTE psp, PBYTE aux_addr, PBYTE &out_res)
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
        printf("hack_etw: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      int state = 0;
      for ( DWORD i = 0; i < 1000; i++ )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( what == aux_addr )
            state = 1;
          continue;
        }
        // check for bl
        PBYTE caddr = NULL;
        if ( state && is_bl_jimm(caddr) )
        {
          out_res = (PBYTE)used_regs.get(AD_REG_X3);
          goto end;
        }
        // check for bl
        if ( state && is_bl_reg() )
        {
          out_res = (PBYTE)used_regs.get(AD_REG_X3);
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
  return (out_res != NULL);
}

int arm64_hack::find_tlgs_guid4(const PBYTE sign, PBYTE mz, std::list<PBYTE> &out_list)
{
  const one_section *s = m_pe->find_section_by_name(".rdata");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  curr++; // tlgProv.Type
  bm_search srch(sign, guid_size);
  while ( curr < end )
  {
    const PBYTE fres = srch.search(curr, end - curr);
    if ( NULL == fres )
      break;
    // check type
    if ( fres[-1] == 4 )
    {
      try
      {
        out_list.push_back(fres);
      } catch(std::bad_alloc)
      { return 0; }
    }
    curr = fres + guid_size;
  }
  if ( out_list.empty() )
    return 0;
  return 1;
}

int arm64_hack::find_tlg_guid4(const PBYTE sign, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".rdata");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  curr++; // tlgProv.Type
  bm_search srch(sign, guid_size);
  std::list<PBYTE> founds;
  while ( curr < end )
  {
    const PBYTE fres = srch.search(curr, end - curr);
    if ( NULL == fres )
      break;
    // check type
    if ( fres[-1] == 4 )
    {
      try
      {
        founds.push_back(fres);
      } catch(std::bad_alloc)
      { return 0; }
    }
    curr = fres + guid_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  out_res = *(founds.cbegin());
  return 1;
}

int arm64_hack::find_etw_guid(const PBYTE sign, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".rdata");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  bm_search srch(sign, guid_size);
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
    curr = fres + guid_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  out_res = *(founds.cbegin());
  return 1;
}

int arm64_hack::find_tlg_by_guid(const PBYTE guid, PBYTE mz, PBYTE &out_res)
{
  PBYTE aux = NULL;
  find_tlg_guid4((const PBYTE)guid, mz, aux);
  if ( aux == NULL )
    return 0;
  return find_tlg_ref(aux + guid_size, mz, out_res);
}

int arm64_hack::find_tlg_by_guid(const PBYTE guid, PBYTE mz, const char *section_name, PBYTE &out_res)
{
  PBYTE aux = NULL;
  find_tlg_guid4((const PBYTE)guid, mz, aux);
  if ( aux == NULL )
    return 0;
  return find_tlg_ref(aux + guid_size, mz, section_name, out_res);
}

int arm64_hack::find_tlgs_by_guid(const PBYTE guid, PBYTE mz, std::list<PBYTE> &out_list)
{
  std::list<PBYTE> aux;
  if ( !find_tlgs_guid4((const PBYTE)guid, mz, aux) )
    return 0;
  for ( auto citer = aux.cbegin(); citer != aux.cend(); ++citer )
  {
    PBYTE tmp = NULL;
    if ( find_tlg_ref(*citer + guid_size, mz, tmp) )
    {
       try
       {
         out_list.push_back(tmp);
       } catch(std::bad_alloc)
       { break; }
    }
  }
  if ( out_list.empty() )
    return 0;
  return 1;
}

int arm64_hack::find_tlg_ref(PBYTE addr, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".data");
  if ( NULL == s )
    return 0;
  UINT64 sign = (UINT64)addr;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  bm_search srch((const PBYTE)&sign, sizeof(sign));
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
    curr = fres + guid_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  out_res = *(founds.cbegin()) - 8;
  return 1;
}

int arm64_hack::find_tlg_ref(PBYTE addr, PBYTE mz, const char *sec_name, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(sec_name);
  if ( NULL == s )
    return 0;
  UINT64 sign = (UINT64)addr;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  bm_search srch((const PBYTE)&sign, sizeof(sign));
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
    curr = fres + guid_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  out_res = *(founds.cbegin()) - 8;
  return 1;
}