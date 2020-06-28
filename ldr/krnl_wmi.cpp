#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

int ntoskrnl_hack::disasm_IoWMIDeviceObjectToProviderId(PBYTE psp, PBYTE &out_call)
{
  if (!setup(psp))
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for KeAcquireSpinLockRaiseToDpc
                 // 1 - call to WmipDoFindRegEntryByDevice
  for ( DWORD i = 0; i < 100; i++ )
  {
    if (!disasm(state) || is_ret())
      break;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      continue;
    }
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( caddr == aux_KeAcquireSpinLockRaiseToDpc )
      {
        state = 1;
        m_WmipRegistrationSpinLock = (PBYTE)used_regs.get(AD_REG_X0);
        continue;
      }
      if ( state )
      {
        out_call = caddr;
        break;
      }
    }
  }
  return (m_WmipRegistrationSpinLock != NULL);
}

int ntoskrnl_hack::disasm_IoWMIQueryAllData(PBYTE psp)
{
  std::set<PBYTE> calls;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while (edge_gen < 100)
  {
    for (auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter)
    {
      psp = *iter;
      if (m_verbose)
        printf("disasm_IoWMIQueryAllData: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      edge_n++;
      for (DWORD i = 0; i < 100; i++)
      {
        if (!disasm() || is_ret())
          break;
        if ( check_jmps(cgraph) )
          continue;
        // check for bl xxx
        PBYTE b_addr = NULL;
        if ( is_bl_jimm(b_addr) )
        {
          if ( in_section(b_addr, "PAGE") )
          {
            try
            {
              calls.insert(b_addr);
            } catch(std::bad_alloc)
            { return 0; }
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
  if ( calls.empty() )
    return 0;
  for ( auto citer = calls.cbegin(); citer != calls.cend(); ++citer )
  {
    if ( try_wmip_obj(*citer) )
      return 1;
  }
  return 0;
}

int ntoskrnl_hack::disasm_WmipDoFindRegEntryByDevice(PBYTE psp)
{
  if (!setup(psp))
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if (!disasm() || is_ret())
      break;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( in_section(what, ".data") )
      {
        m_WmipInUseRegEntryHead = what;
        break;
      }
    }
  }
  return (m_WmipInUseRegEntryHead != NULL);
}

int ntoskrnl_hack::try_wmip_obj(PBYTE psp)
{
  if (!setup(psp))
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if (!disasm() || is_ret())
      break;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "ALMOSTRO") )
        used_regs.zero(get_reg(0));  
    }
    // check for call
    PBYTE b_addr = NULL;
    if ( is_bl_jimm(b_addr) )
    {
      if ( (b_addr == aux_ObReferenceObjectByPointer) ||
           (b_addr == aux_ObReferenceObjectByHandle) // 19603
         )
      {
        m_WmipGuidObjectType = (PBYTE)used_regs.get(AD_REG_X2);
        break;
      }
    }
  }
  return (m_WmipGuidObjectType != NULL);
}
