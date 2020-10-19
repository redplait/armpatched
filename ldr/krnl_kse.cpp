#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_kse()
{
  m_KseEngine = m_kse_lock = NULL;
  m_IopUpdatePriorityCallback_size = 0;
  m_IopUpdatePriorityCallbackRoutine = m_IopUpdatePriorityCallbackRoutineCount = NULL;
}

void ntoskrnl_hack::dump_kse(PBYTE mz) const
{
  if ( m_KseEngine != NULL )
    printf("KseEngine: %p\n", PVOID(m_KseEngine - mz));
  if ( m_kse_lock != NULL )
    printf("kse_lock: %p\n", PVOID(m_kse_lock - mz));
  if ( m_IopUpdatePriorityCallbackRoutine != NULL )
    printf("IopUpdatePriorityCallbackRoutine: %p\n", PVOID(m_IopUpdatePriorityCallbackRoutine - mz));
  if ( m_IopUpdatePriorityCallbackRoutineCount != NULL )
    printf("IopUpdatePriorityCallbackRoutineCount: %p\n", PVOID(m_IopUpdatePriorityCallbackRoutineCount - mz));
  if ( m_IopUpdatePriorityCallback_size )
    printf("IopUpdatePriorityCallback size: %X\n", m_IopUpdatePriorityCallback_size);
}

struct state_regs
{
  regs_pad regs;
  int state;

  state_regs()
  {
    state = 0;
  }
  bool operator<(const state_regs& s) const
  {
    return this->state < s.state;
  }
};

int ntoskrnl_hack::disasm_KseUnregisterShim(PBYTE psp)
{
  statefull_graph<PBYTE, state_regs> cgraph;
  std::list<std::pair<PBYTE, state_regs> > addr_list;
  state_regs tmp;
  auto curr = std::make_pair(psp, tmp);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
    {
      psp = iter->first;
      int state = iter->second.state;
      if ( m_verbose )
        printf("disasm_KseUnregisterShim: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, iter->second) )
          continue;
        if ( is_adrp(iter->second.regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)iter->second.regs.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !state && in_section(what, ".data") )
          {
            state = iter->second.state = 1;
            m_KseEngine = what;
            continue;
          }
        }
        PBYTE addr = NULL;
        if ( state && is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAcquirePushLockExclusiveEx )
          {
            m_kse_lock = (PBYTE)iter->second.regs.get(AD_REG_X0);
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
  return is_kse_ok();
}

int ntoskrnl_hack::disasm_IoRegisterPriorityCallback(PBYTE psp)
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
        printf("disasm_IoRegisterPriorityCallback: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      int size = 0;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        // mov reg, imm
        if ( !state && is_mov_rimm() )
        {
          used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
          continue;
        }
        // call
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAllocatePoolWithTag || addr == aux_ExAllocatePool2 )
          {
            m_IopUpdatePriorityCallback_size = (DWORD)used_regs.get(AD_REG_X1);
            state = 1;
            continue;
          }
        }
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            continue;
          if ( m_IopUpdatePriorityCallbackRoutine == NULL )
          {
            m_IopUpdatePriorityCallbackRoutine = what;
            continue;
          }
          if ( what != m_IopUpdatePriorityCallbackRoutine )
          {
            m_IopUpdatePriorityCallbackRoutineCount = what;
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
  return is_iopc_ok();
}
