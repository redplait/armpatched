#include "stdafx.h"
#include "deriv.h"
#include "bm_search.h"

int validate_scan(Rules_set &rules_set, path_edge &edge)
{
  if ( !edge.is_scan() )
    return 0;
  for ( const auto item: edge.scan_list )
  {
    int rule_no = 0;
    if ( item.is_rule(rule_no) )
    {
      const auto citer = rules_set.find(rule_no);
      if ( citer == rules_set.cend() )
      {
        fprintf(stderr, "no rule %d exists for scan at line %d\n", rule_no, edge.m_line);
        return 0;
      }
    }
  }
  return 1;
}

int deriv_hack::check_rule_results(found_xref &xref, Rules_set &rules_set, int rule_no)
{
  auto iter = rules_set.find(rule_no);
  if ( iter == rules_set.end() )
    return 0;
  auto res_iter = rules_result.find(rule_no);
  if ( res_iter != rules_result.end() )
    return !res_iter->second.empty();
  // ok, we evaluate this rule first time
  prepare(xref, iter->second);
  std::set<PBYTE> candidates;
  DWORD found = 0;
  int res = apply(xref, iter->second, found, &candidates);
  rules_result[rule_no] = std::move(candidates);
  return res;
}

int deriv_hack::scan_value(found_xref &xref, bm_search &bm, int pattern_size, path_edge &path, Rules_set &rules_set, std::set<PBYTE> &results)
{
  const one_section *s = m_pe->find_section_by_name(path.symbol_section.c_str());
  if ( s == NULL )
  {
    printf("cannot find section %s\n", path.symbol_section.c_str());
    return 0;
  }
  auto iter = path.scan_list.begin();
  // calc max size of data
  DWORD size = iter->get_upper_bound();
  std::for_each(path.scan_list.cbegin(), path.scan_list.cend(), [&size](const path_item &item) { auto curr_size = item.get_upper_bound(); if (curr_size > size) size = curr_size; });
  if (size > s->size)
  {
    printf("section %s is too small, size %d, needed %d\n", path.symbol_section.c_str(), s->size, size);
    return 0;
  }
  PBYTE mz = m_pe->base_addr();
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size - size;
  curr += iter->at;
  int res = 0;
  while ( curr < end )
  {
     PBYTE fres = bm.search(curr, end - curr);
     if ( NULL == fres )
       break;
     if ( is_inside_fids_table(fres) )
     {
       curr = fres + pattern_size;
       continue;
     }
     PBYTE tab = fres - iter->at;
     auto tail_iter = iter;
     ++tail_iter;
     int is_ok = (tail_iter == path.scan_list.end());
     for ( ; tail_iter != path.scan_list.end(); ++tail_iter)
     {

     }
     if ( is_ok )
     {
       results.insert(tab);
       res++;
     }
     // for next iteration
     curr = fres + pattern_size;
  }
  return res;
}

int deriv_hack::apply_scan(found_xref &xref, path_edge &path, Rules_set &rules_set)
{
  auto iter = path.scan_list.begin();
  DWORD call_addr = 0;
  const export_item *exp = NULL;
  UINT64 sign;
  int pattern_size = sizeof(sign);
  PBYTE mz = m_pe->base_addr();
  bm_search srch;
  std::set<PBYTE> results;
  switch(iter->type)
  {
    case rule:
      if ( !check_rule_results(xref, rules_set, iter->reg_index) )
        return 0;
      else {
        const auto &found = rules_result[iter->reg_index];
        for ( const auto &cf: found )
        {
          sign = m_pe->image_base() + UINT64(cf - mz);
          srch.set((const PBYTE)&sign, pattern_size);
          scan_value(xref, srch, pattern_size, path, rules_set, results);
        }
        goto process_results;
      }
     break;
    case call_exp:
      exp = m_ed->find(iter->name.c_str());
      if ( exp == NULL )
      {
        fprintf(stderr, "cannot find exported function %s for scan at line %d\n", iter->name.c_str(), path.m_line);
        return 0;
      }
      call_addr = exp->rva;
      sign = UINT64(m_pe->image_base() + call_addr);
      srch.set((const PBYTE)&sign, pattern_size);
     break;
    case call_imp:
      call_addr = get_iat_by_name(iter->name.c_str());
      if ( !call_addr )
      {
        fprintf(stderr, "cannot find imported function %s for scan at line %d\n", iter->name.c_str(), path.m_line);
        return 0;
      }
      sign = UINT64(m_pe->image_base() + call_addr);
      srch.set((const PBYTE)&sign, pattern_size);
     break;
    case call_dimp:
      call_addr = get_diat_by_name(iter->name.c_str());
      if ( !call_addr )
      {
        fprintf(stderr, "cannot find delayed imported function %s for scan at line %d\n", iter->name.c_str(), path.m_line);
        return 0;
      }
      sign = UINT64(m_pe->image_base() + call_addr);
      srch.set((const PBYTE)&sign, pattern_size);
     break;
    case ldr_guid:
       pattern_size = sizeof(iter->guid);
       srch.set((const PBYTE)&iter->guid, pattern_size);
      break;
    default:
     fprintf(stderr, "unknown type %d in scan at line %d\n", iter->type, path.m_line);
     return 0;
  }
  // scan
  scan_value(xref, srch, pattern_size, path, rules_set, results);
process_results:
  // process results
  if ( results.empty() )
    return 0;
  if ( results.size() > 1 )
  {
     fprintf(stderr, "ambigious relusts for scan at line %d, found %d cadidates\n", path.m_line, (int)results.size());
     fprintf(stderr, "candidates:\n");
     for ( const auto cand: results )
       fprintf(stderr, " %p\n", cand - mz);
     return 0;
  }
  // store
  store_stg(path.m_rule, *(results.cbegin()) - mz);
  return 1;
}