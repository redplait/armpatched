#include "stdafx.h"
#include "skci_hack.h"
#include "cf_graph.h"

void skci_hack::zero_data()
{
  m_CipPolicyLock = NULL;
  m_CiOptions = m_CiDeveloperMode = NULL;
}

void skci_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_CipPolicyLock != NULL )
    printf("g_CipPolicyLock: %p\n", PVOID(m_CipPolicyLock - mz));
  if ( m_CiOptions != NULL )
    printf("g_CiOptions: %p\n", PVOID(m_CiOptions - mz));
  if ( m_CiDeveloperMode != NULL )
    printf("g_CiDeveloperMode: %p\n", PVOID(m_CiDeveloperMode - mz));
}

int skci_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("SkciQueryInformation");
  if ( exp != NULL )
    res += hack_gci(mz + exp->rva);
  return res;
}


int skci_hack::hack_gci(PBYTE psp)
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
        printf("hack_gci: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        if ( is_ldar(used_regs) || is_mov_rr(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !state )
          {
            if ( !is_inside_IAT(what) )
            {
              if ( !in_section(what, ".data") )
                used_regs.zero(get_reg(0));
            }
          }
        }
        // call reg
        if ( is_bl_reg() )
        {
          if ( state )
            break;
          PBYTE what = (PBYTE)used_regs.get(get_reg(0));
          if ( is_iat_func(what, "SkAcquirePushLockShared") )
          {
            state = 1;
            m_CipPolicyLock = (PBYTE)used_regs.get(AD_REG_X0);
          }
        }
        // ldr
        if ( state && is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
          else
          {
            if ( 1 == state )
            {
              m_CiOptions = what;
              state = 2;
            } else if ( 2 == state )
            {
              m_CiDeveloperMode = what;
              goto end;
            }
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
  return (m_CiOptions != NULL) && (m_CiDeveloperMode != NULL);
}