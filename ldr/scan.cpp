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

int deriv_hack::resolve_rules(path_edge &path, Rules_set &rules_set)
{
  std::set<int> resolved;
  return _resolve_rules(path, rules_set, resolved);
}

// recursive resolve rules
int deriv_hack::_resolve_rules(path_edge &path, Rules_set &rules_set, std::set<int> &resolved)
{
  if ( path.is_scan() )
  {
    for ( auto &r: path.scan_list )
    {
      int rule_no = 0;
      if ( r.is_rule(rule_no) )
      {
        // check if this rule already was processed
        auto checked = resolved.find(rule_no);
        if ( checked != resolved.end() )
          continue;
        auto rule = rules_set.find(rule_no);
        if ( rule == rules_set.end() )
        {
          fprintf(stderr, "cannot find rule %d for scan at line %d\n", rule_no, path.m_line);
          return 0;
        }
        if ( !_resolve_rules(rule->second, rules_set, resolved) )
          return 0;
        resolved.insert(rule_no);
      }
      return 1;
    }
  } else {
    // delete all rule after filling apply_rule field
    if ( path.list.empty() )
      return 1;
    auto iter = path.list.begin();
    int rule_no = 0;
    if ( iter->is_rule(rule_no) )
    {
      fprintf(stderr, "you can`t have rule as first item at line %d\n", path.m_line);
      return 0;
    }
    path_item *prev = &(*iter);
    for ( ++iter; iter != path.list.end(); )
    {
      if ( iter->is_rule(rule_no) )
      {
        // check if previous item can have rule
        if ( !prev->can_have_rule() )
        {
          fprintf(stderr, "you can`t apply rule to item with type %d at line %d\n", prev->type, path.m_line);
          return 0;
        }
        if ( prev->apply_rule != NULL )
        {
          fprintf(stderr, "you can`t have several rule for item with type %d at line %d\n", prev->type, path.m_line);
          return 0;
        }
        auto rule = rules_set.find(rule_no);
        if ( rule == rules_set.end() )
        {
          fprintf(stderr, "cannot find rule %d at line %d\n", rule_no, path.m_line);
          return 0;
        }
        prev->apply_rule = &rule->second;
        // remove this item
        iter = path.list.erase(iter);
        // we already checked this?
        auto checked = resolved.find(rule_no);
        if ( checked != resolved.end() )
          continue;
        resolved.insert(rule_no);
        if ( !_resolve_rules(rule->second, rules_set, resolved) )
          return 0;        
        continue;
      }
      prev = &(*iter);
      ++iter;
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

int deriv_hack::scan_thunk(path_edge &path, DWORD &out_value)
{
  const one_section *s = m_pe->find_section_by_name(path.symbol_section.c_str());
  if ( s == NULL )
  {
    printf("scan_thunk: cannot find section %s\n", path.symbol_section.c_str());
    return 0;
  }
  auto iter = path.scan_list.begin();
  // calc max size of data
  DWORD size = path.get_scan_max_size();
  if (size > s->size)
  {
    printf("scan_thunk: section %s is too small, size %d, needed %d\n", path.symbol_section.c_str(), s->size, size);
    return 0;
  }
  PBYTE mz = m_pe->base_addr();
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size - size;
  for ( curr += iter->at; curr < end; curr += iat_mod::ptr_size )
  {
    uint64_t val = *(uint64_t *)curr;
    if ( !val )
      continue;
    DWORD off = DWORD(val - (uint64_t)mz);
    if ( !in_executable_section(off) )
      continue;
    if ( check_thunk(off, iter->name.c_str()) )
    {
      out_value = off;
      return 1;
    }
  }
  return 0;
}

DWORD path_edge::get_scan_max_size() const
{
  auto iter = scan_list.cbegin();
  // calc max size of data
  DWORD size = iter->get_upper_bound();
  std::for_each(scan_list.cbegin(), scan_list.cend(), [&size](const path_item &item) { auto curr_size = item.get_upper_bound(); if (curr_size > size) size = curr_size; });
  return size;
}

int deriv_hack::scan_value(found_xref &xref, bm_search &bm, int pattern_size, path_edge &path, Rules_set &rules_set, std::set<PBYTE> &results)
{
  const one_section *s = m_pe->find_section_by_name(path.symbol_section.c_str());
  if ( s == NULL )
  {
    printf("scan_value: cannot find section %s\n", path.symbol_section.c_str());
    return 0;
  }
  auto iter = path.scan_list.begin();
  // calc max size of data
  DWORD size = path.get_scan_max_size();
  if (size > s->size)
  {
    printf("scan_value: section %s is too small, size %d, needed %d\n", path.symbol_section.c_str(), s->size, size);
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
       switch (tail_iter->type)
       {
         case ldr_off:
            is_ok = *(PDWORD)(tab + tail_iter->at) == tail_iter->value;
           break;
         case ldr64_off:
            is_ok = *(uint64_t *)(tab + tail_iter->at) == tail_iter->value64;
           break;
         case sload:
           {
             DWORD off = *(UINT64 *)(tab + tail_iter->at) - m_pe->image_base();
             auto s = m_pe->find_section_v(off);
             if (s != NULL)
               is_ok = !strcmp(s->name, tail_iter->name.c_str());
             else
               is_ok = 0;
           }
           break;
         case poi:
            is_ok = *(UINT64 *)(tab + tail_iter->at) == *(UINT64 *)(mz + tail_iter->rva + tail_iter->value);
           break;
         case call_imp:
           {
             DWORD off = *(UINT64 *)(tab + tail_iter->at) - m_pe->image_base();
             is_ok = check_thunk(off, tail_iter->name.c_str());
           }
           break;
         case gload:
         case gcall:
         case call_exp:
         case call_dimp:
           is_ok = ( *(UINT64 *)(tab + tail_iter->at) - m_pe->image_base() == tail_iter->rva );
          break;
         case ldr_guid:
           is_ok = !memcmp(tab + tail_iter->at, tail_iter->guid, sizeof(tail_iter->guid));
          break;
         case rule:
           {
             auto eved = rules_result.find(tail_iter->reg_index);
             // lets see if this rule already was evaluated
             if ( eved == rules_result.end() )
             {
               if ( !check_rule_results(xref, rules_set, tail_iter->reg_index) )
                 return 0;
               eved = rules_result.find(tail_iter->reg_index);
             }
             if ( eved == rules_result.end() )
                return 0;
             for ( auto early: eved->second )
             {
               // we want any match in results of this rule
               UINT64 has = early - mz + m_pe->image_base();
               if ( has == *(UINT64 *)(tab + tail_iter->at) )
               {
                 is_ok = 1;
                 break;
               }
             }
           }
          break;
         default:
          fprintf(stderr, "unknown type %d in scan_value at line %d\n", tail_iter->type, path.m_line);
       }
       if (!is_ok)
         break;
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

int deriv_hack::validate_scan_items(path_edge &edge)
{
  for ( auto& item: edge.scan_list )
  {
    if ( item.type == call_exp )
    {
      const export_item *exp = m_ed->find(item.name.c_str());
      if ( exp == NULL && has_ord_prefix(item.name.c_str()) )
      {
        int ord = atoi(item.name.c_str() + 3);
        exp = m_ed->find(ord);
      }
      if ( exp == NULL )
      {
        fprintf(stderr, "cannot find exported function %s for scan at line %d\n", item.name.c_str(), edge.m_line);
        return 0;
      }
      item.rva = exp->rva;
    } else if ( item.type == call_imp )
    {
      item.rva = get_iat_by_name(item.name.c_str());
      if ( !item.rva )
      {
        fprintf(stderr, "cannot find imported function %s for scan at line %d\n", item.name.c_str(), edge.m_line);
        return 0;
      }
    } else if ( item.type == call_dimp )
    {
      item.rva = get_diat_by_name(item.name.c_str());
      if ( !item.rva )
      {
        fprintf(stderr, "cannot find delayed imported function %s for scan at line %d\n", item.name.c_str(), edge.m_line);
        return 0;
      }
    } else if ( item.type == poi )
    {
      auto found = m_stg.find(item.reg_index);
      if ( found == m_stg.end() )
      {
        fprintf(stderr, "nothing was found with storage index %d for scan at line %d\n", item.reg_index, edge.m_line);
        return 0;
      }
      item.rva = found->second;      
    } else if ( (item.type == gcall) || (item.type == gload) )
    {
      auto found = m_stg.find(item.stg_index);
      if ( found == m_stg.end() )
      {
        fprintf(stderr, "nothing was found with storage index %d for scan at line %d\n", item.stg_index, edge.m_line);
        return 0;
      }
      item.rva = found->second;
    } else if ( item.type == sload )
    {
      auto s = m_pe->find_section_by_name(item.name.c_str());
      if ( s == NULL )
      {
        fprintf(stderr, "no section %s for scan at line %d\n", item.name.c_str(), edge.m_line);
        return 0;
      }
    }
  }
  return 1;
}

int deriv_hack::apply_scan(found_xref &xref, path_edge &path, Rules_set &rules_set)
{
  if ( !validate_scan_items(path) )
    return 0;
  auto iter = path.scan_list.begin();
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
    case sload:
     fprintf(stderr, "you cant have sload as first rule for scan at line %d\n", path.m_line);
     return 0;
    case poi:
      sign = *(UINT64 *)(mz + iter->rva + iter->value);
      srch.set((const PBYTE)&sign, pattern_size);
     break;
    case call_imp:
     {
       DWORD cached = 0;
       if ( find_thunk_byname(iter->name.c_str(), cached) )
       {
         sign = UINT64(m_pe->image_base() + cached);
         srch.set((const PBYTE)&sign, pattern_size);
       } else {
         // we need to scan whole section content to find right import thunk
         if ( !scan_thunk(path, cached) )
         {
           fprintf(stderr, "cant find thunk for import %s for scan at line %d\n", iter->name.c_str(), path.m_line);
           return 0;
         }
         sign = UINT64(m_pe->image_base() + cached);
         srch.set((const PBYTE)&sign, pattern_size);
       }
     }
     break;
    case gload:
    case gcall:
    case call_dimp:
    case call_exp:
      sign = UINT64(m_pe->image_base() + iter->rva);
      srch.set((const PBYTE)&sign, pattern_size);
     break;
    case ldr_off:
      pattern_size = sizeof(iter->value);
      srch.set((const PBYTE)&iter->value, pattern_size);
     break;
    case ldr64_off:
      pattern_size = sizeof(iter->value64);
      srch.set((const PBYTE)&iter->value64, pattern_size);
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
     fprintf(stderr, "ambigious relusts for scan at line %d, found %d cadidates:\n", path.m_line, (int)results.size());
     for ( const auto cand: results )
       fprintf(stderr, " %p\n", cand - mz);
     return 0;
  }
  // store
  store_stg(path.m_rule, *(results.cbegin()) - mz);
  return 1;
}