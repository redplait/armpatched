#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_po()
{
  m_PoRegisterPowerSettingCallback_size = 0;
  m_PopSettingLock = m_PopRegisteredPowerSettingCallbacks = NULL;
}

void ntoskrnl_hack::dump_po(PBYTE mz) const
{
  if ( m_PopSettingLock != NULL )
    printf("PopSettingLock: %p\n", PVOID(m_PopSettingLock - mz));
  if ( m_PopRegisteredPowerSettingCallbacks != NULL )
  {
    printf("PopRegisteredPowerSettingCallbacks: %p\n", PVOID(m_PopRegisteredPowerSettingCallbacks - mz));
    if ( m_PoRegisterPowerSettingCallback_size )
      printf("PopRegisteredPowerSettingCallback size: %X\n", m_PoRegisterPowerSettingCallback_size);
  }
}

// state:
//  0 - wait for ExAcquireFastMutex
//  1 - wait for ExAllocatePoolWithTag
//  2 - wait for loading of list from .data
int ntoskrnl_hack::disasm_PoRegisterPowerSettingCallback(PBYTE psp)
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
        printf("disasm_PoRegisterPowerSettingCallback: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        // mov reg, imm
        if ( (1 == state) && is_mov_rimm() )
        {
          used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
          continue;
        }
        // check calls
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAllocatePoolWithTag || addr == aux_ExAllocatePool2 )
          {
            m_PoRegisterPowerSettingCallback_size = (DWORD)used_regs.get(AD_REG_X1);
            state = 2;
            continue;
          }
          if ( !state && addr == aux_ExAcquireFastMutex )
          {
            m_PopSettingLock = (PBYTE)used_regs.get(AD_REG_X0);
            state = 1;
          }
          if ( state && addr == aux_memcmp )
            break;
        }
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            continue;
          if ( (state == 2) && (what != m_PopSettingLock) )
          {
            m_PopRegisteredPowerSettingCallbacks = what;
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
  return is_po_cbs_ok();
}