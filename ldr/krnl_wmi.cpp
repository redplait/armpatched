#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_wmi()
{
  m_WmipGuidObjectType = m_WmipRegistrationSpinLock = m_WmipInUseRegEntryHead = NULL;
  m_EtwSiloState_offset = m_etw_guid_entry_size = m_ejob_silo_globals_offset = 0;
  m_wmi_logger_ctx_size = m_wmi_logger_ctx_loggername_offset = m_wmi_logger_ctx_starttime_offset = 0;
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
  if ( m_wmi_logger_ctx_size )
    printf("WMI_LOGGER_CONTEXT size: %X\n", m_wmi_logger_ctx_size);
  if ( m_wmi_logger_ctx_loggername_offset )
    printf("WMI_LOGGER_CONTEXT.LoggerName offset: %X\n", m_wmi_logger_ctx_loggername_offset);
  if ( m_wmi_logger_ctx_starttime_offset )
    printf("WMI_LOGGER_CONTEXT.StartTime offset: %X\n", m_wmi_logger_ctx_starttime_offset);
  if ( m_ejob_silo_globals_offset )
    printf("EJOB.ServerSiloGlobals offset: %X\n", m_ejob_silo_globals_offset);
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

  res += find_EtwpInitLoggerContext_by_sign(mz);
  return res;
}

static const DWORD s_tag = 0x47777445;
static const DWORD s_wmi_logger_ctx_tag = 0x4C777445;

int ntoskrnl_hack::find_EtwpInitLoggerContext_by_sign(PBYTE mz)
{
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
  bm_search srch((const PBYTE)&s_wmi_logger_ctx_tag, sizeof(s_wmi_logger_ctx_tag));
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
    printf("find_EtwpInitLoggerContext_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( hack_EtwpInitLoggerContext(func, mz) )
      return 1;
  }
  return 0;
}

struct wmi_state
{
  int state;  // 0 - wait allocation, 1 - store x0 to res_reg, > 1 - wait add reg, res_reg or call to RtlInitUnicodeString/KeQuerySystemTimePrecise
  int res_reg;
  wmi_state()
  {
    state = 0;
    res_reg = -1;
  }
  wmi_state(wmi_state &&) = default;
  wmi_state(const wmi_state &) = default;
  wmi_state &operator=(const wmi_state &) = default;
  bool operator<(const wmi_state& s) const
  {
    return (state < s.state);
  }
};

int ntoskrnl_hack::hack_EtwpInitLoggerContext(PBYTE psp, PBYTE mz)
{
  PBYTE qtime = NULL;
  const export_item *exp = m_ed->find("KeQuerySystemTimePrecise");
  if ( exp != NULL )
    qtime = mz + exp->rva;
  statefull_graph<PBYTE, wmi_state> cgraph;
  std::list<std::pair<PBYTE, wmi_state> > addr_list;
  wmi_state tmp;
  auto curr = std::make_pair(psp, tmp);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  int res = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.begin(); iter != addr_list.end(); ++iter )
    {
      psp = iter->first;
      if ( m_verbose )
        printf("hack_EtwpInitLoggerContext: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      edge_n++;
      DWORD last_add = 0;
      for ( DWORD i = 0; i < 1000; i++ )
      {
        if ( !disasm(iter->second.state) || is_ret() )
          break;
        if ( check_jmps(cgraph, iter->second) )
          continue;
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr, iter->second);
          break;
        }
        // mov reg, x0
        if ( is_mov_rr() && (1 == iter->second.state) && get_reg(1) == AD_REG_X0 )
        {
          iter->second.state = 2;
          iter->second.res_reg = get_reg(0);
          continue;
        }
        // add reg, res_reg
        if ( (iter->second.state > 1) && is_add() && get_reg(1) == iter->second.res_reg )
        {
           last_add = (DWORD)m_dis.operands[2].op_imm.bits;
           if ( iter->second.state == 2 && !m_wmi_logger_ctx_size )
           {
             m_wmi_logger_ctx_size = last_add;
             last_add = 0;
             ++iter->second.state;
           }
        }
        // check for call jimm
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAllocatePoolWithTag ||
               addr == aux_ExAllocatePool2
             )
          {
            iter->second.state = 1;
            continue;
          }
          if ( addr == aux_RtlInitUnicodeString )
          {
            m_wmi_logger_ctx_loggername_offset = last_add;
            continue;
          }
          if ( addr == qtime )
          {
            m_wmi_logger_ctx_starttime_offset = last_add;
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
  return is_wmi_ctx_ok();
}

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
      if ( b_addr == aux_ExAllocatePoolWithTag ||
           b_addr == aux_ExAllocatePool2
         )
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