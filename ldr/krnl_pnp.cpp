#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::dump_pnp(PBYTE mz) const
{
  if ( m_PnpDeviceClassNotifyLock != NULL )
    printf("PnpDeviceClassNotifyLock: %p\n", PVOID(m_PnpDeviceClassNotifyLock - mz));
  if ( m_PnpDeviceClassNotifyList != NULL )
    printf("PnpDeviceClassNotifyList: %p, item_size %X\n", PVOID(m_PnpDeviceClassNotifyList - mz), m_pnp_item_size);
}

static const DWORD s_tag = 0x44706E50;

// state - 0 - wait for tag
//         1 - wait for ExAllocatePoolWithTag
//         2 - KeAcquireGuardedMutex/ExAcquireFastMutex
//         3 - wait for PnpDeviceClassNotifyList
int ntoskrnl_hack::disasm_IoRegisterPlugPlayNotification(PBYTE psp)
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
        printf("disasm_IoRegisterPlugPlayNotification: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
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
        if ( !state && is_ldr_off() )
        {
          DWORD tmp = *(PDWORD)m_dis.operands[1].op_imm.bits;
          if ( tmp == s_tag )
           state = 1;
        }
        // mov x1, imm
        if ( (1 == state) && is_mov_rimm() && get_reg(0) == AD_REG_X1 )
          m_pnp_item_size = (DWORD)m_dis.operands[1].op_imm.bits;
        // bl
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( state && addr == aux_ExAllocatePoolWithTag )
            state = 2;
          else if ( addr == aux_ExAcquireFastMutex || addr == aux_KeAcquireGuardedMutex)
          {
            if (state)
            {
              m_PnpDeviceClassNotifyLock = (PBYTE)used_regs.get(AD_REG_X0);
              state = 3;
            }
          }
        }
        if ( state && is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( 3 == state && in_section(what, "PAGEDATA") )
          {
             m_PnpDeviceClassNotifyList = what;
             goto end;
          }
          if ( state == 2 && !in_section(what, ".data") )
             used_regs.zero(get_reg(0));
          continue;
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
  return ( m_PnpDeviceClassNotifyList != NULL );
}