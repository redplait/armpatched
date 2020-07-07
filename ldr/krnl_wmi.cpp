#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_wmi()
{
  m_WmipGuidObjectType = m_WmipRegistrationSpinLock = m_WmipInUseRegEntryHead = NULL;
  m_EtwSiloState_offset = m_etw_guid_entry_size = 0;
}

void ntoskrnl_hack::dump_wmi(PBYTE mz) const
{
  if ( m_WmipGuidObjectType != NULL )
    printf("WmipGuidObjectType: %p\n", PVOID(m_WmipGuidObjectType - mz));
  if ( m_WmipRegistrationSpinLock != NULL )
    printf("WmipRegistrationSpinLock: %p\n", PVOID(m_WmipRegistrationSpinLock - mz));
  if ( m_WmipInUseRegEntryHead != NULL )
    printf("WmipInUseRegEntryHead: %p\n", PVOID(m_WmipInUseRegEntryHead - mz));
  if ( m_EtwSiloState_offset )
    printf("ESERVERSILO_GLOBALS.EtwSiloState offset: %X\n", m_EtwSiloState_offset);
  if ( m_etw_guid_entry_size )
    printf("ETW_GUID_ENTRY size: %X\n", m_etw_guid_entry_size);
}

int ntoskrnl_hack::hack_wmi(PBYTE mz)
{
  int res = 0;
  const export_item *exp = m_ed->find("IoWMIQueryAllData");
  if ( exp != NULL )
    res += disasm_IoWMIQueryAllData(mz + exp->rva);
  exp = m_ed->find("IoWMIDeviceObjectToProviderId");
  if ( exp != NULL )
  {
    PBYTE res_call = NULL;
    res += disasm_IoWMIDeviceObjectToProviderId(mz + exp->rva, res_call);
    if ( res_call != NULL )
      res += disasm_WmipDoFindRegEntryByDevice(res_call);
  }
  exp = m_ed->find("WmiGetClock");
  if ( exp != NULL )
    res += hack_wmi_clock(mz + exp->rva);
  if ( m_EtwSiloState_offset )
    res += find_EtwpAllocGuidEntry_by_sign(mz);

  return res;
}

static const DWORD s_tag = 0x47777445;

int ntoskrnl_hack::hack_EtwpAllocGuidEntry(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 30; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_mov_rimm() )
    {
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      continue;
    }
    PBYTE b_addr = NULL;
    if ( is_bl_jimm(b_addr) )
    {
      if ( b_addr == aux_ExAllocatePoolWithTag )
        m_etw_guid_entry_size = (DWORD)used_regs.get(AD_REG_X1);
      break;
    }
  }
  return (m_etw_guid_entry_size != 0);
}

int ntoskrnl_hack::find_EtwpAllocGuidEntry_by_sign(PBYTE mz)
{
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
  bm_search srch((const PBYTE)&s_tag, sizeof(s_tag));
  PBYTE curr = start;
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
    curr = fres + sizeof(s_tag);
  }
  if ( founds.empty() )
    return 0;
  for ( auto citer = founds.cbegin(); citer != founds.cend(); ++citer )
  {
    PBYTE func = find_pdata(*citer);
    if ( NULL == func )
      continue;
#ifdef _DEBUG
    printf("find_EtwpAllocGuidEntry_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( hack_EtwpAllocGuidEntry(func) )
      return 1;
  }
  return 0;
  
}

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

int ntoskrnl_hack::hack_wmi_clock(PBYTE psp)
{
  if (!setup(psp))
    return 0;
  int state = 0;
  for ( DWORD i = 0; i < 20; i++ )
  {
    if (!disasm() || is_ret())
      break;
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
       if ( !state )
       {
         aux_PsGetCurrentServerSiloGlobals = caddr;
         state = 1;
         continue;
       }
       break;
    }
    // after call to PsGetCurrentServerSiloGlobals I expect something like ldr reg, [x0 + offset]
    if ( state && is_ldr() && (get_reg(1) == AD_REG_X0) )
    {
      m_EtwSiloState_offset = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
  }
  return (m_EtwSiloState_offset != 0);
}