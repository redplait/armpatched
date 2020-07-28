#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_etw()
{
  m_CmpTraceRoutine = NULL;
  m_EtwpRegistrationObjectType = m_EtwpSessionDemuxObjectType = NULL;
  m_etw_handles = {
    // 0) EventTracingProvGuid
    { { 0x37, 0xEC, 0x75, 0xB6, 0xB6, 0xBD, 0x48, 0x46, 0xBC, 0x92, 0xF3, 0xFD, 0xC7, 0x4D, 0x3C, 0xA2 },
      "EtwpEventTracingProvRegHandle", NULL, NULL },
    // 1) KernelProvGuid
    { { 0xB7, 0xA8, 0x8C, 0xA6, 0x4F, 0, 0xB6, 0xD7, 0xA6, 0x98, 7, 0xE2, 0xDE, 0xF, 0x1F, 0x5D },
      "EtwKernelProvRegHandle", NULL, NULL },
    // 2) PsProvGuid
    { { 0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0xE, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 },
       "EtwpPsProvRegHandle", NULL, NULL },
    // 3) NetProvGuid
    { { 0x49, 0x2A, 0xD4, 0x7D, 0x29, 0x53, 0x32, 0x48, 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 },
      "EtwpNetProvRegHandle", NULL, NULL },
    // 4) DiskProvGuid
    { { 0x9A, 0xE6, 0xBD, 0xC7, 0xE0, 0xE1, 0x77, 0x41, 0xB6, 0xEF, 0x28, 0x3A, 0xD1, 0x52, 0x52, 0x71 },
      "EtwpDiskProvRegHandle", NULL, NULL },
    // 5) FileProvGuid
    { { 0x27, 0x89, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0xF, 0xB5, 0xC2, 0x89 },
      "EtwpFileProvRegHandle", NULL, NULL },
    // 6) RegistryProvGuid - in build 20xxx?
    { { 3, 0x4F, 0xEB, 0x70, 0xDE, 0xC1, 0x73, 0x4F, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD },
      "EtwpRegTraceHandle", NULL, NULL },
    // 7) MemoryProvGuid
    { { 0xF7, 0x3E, 0xD9, 0xD1, 0xF2, 0xE1, 0x45, 0x4F, 0x99, 0x43, 3, 0xD2, 0x45, 0xFE, 0x6C, 0 },
      "EtwpMemoryProvRegHandle", NULL, NULL },
    // 8) MS_Windows_Kernel_AppCompat_Provider
    { { 0xC1, 0xAD, 0xA1, 0x16, 0x7F, 0x9B, 0xD9, 0x4C, 0x94, 0xB3, 0xD8, 0x29, 0x6A, 0xB1, 0xB1, 0x30 },
      "EtwAppCompatProvRegHandle", NULL, NULL },
    // 9) KernelAuditApiCallsGuid
    { { 0x1C, 0x84, 0x2A, 0xE0, 0xA3, 0x75, 0xA7, 0x4F, 0xAF, 0xC8, 0xAE, 9, 0xCF, 0x9B, 0x7F, 0x23 },
      "EtwApiCallsProvRegHandle", NULL, NULL },
    // 10) CVEAuditProviderGuid
    { { 0xD, 0x2A, 0xA6, 0x85, 0x17, 0x7E, 0x5F, 0x48, 0x9D, 0x4F, 0x74, 0x9A, 0x28, 0x71, 0x93, 0xA6 },
      "EtwCVEAuditProvRegHandle", NULL, NULL },
    // 11) ThreatIntProviderGuid
    { { 0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 4, 0xF, 0x4D, 0x8D, 0xD3, 0x44 },
      "EtwThreatIntProvRegHandle", NULL, NULL },
    // 12) MS_Windows_Security_LPAC_Provider
    { { 0xE5, 0xC9, 0xEE, 0x45, 0x1B, 0x4A, 0x46, 0x54, 0x7A, 0xD8, 0xA4, 0xAB, 0x13, 0x13, 0xC4, 0x37 },
      "EtwLpacProvRegHandle", NULL, NULL },
    // 13) MS_Windows_Security_Adminless_Provider
    { { 0x62, 0x69, 0x21, 0xEA, 0x7B, 0x87, 0x73, 0x5B, 0xF7, 0xC5, 0x8A, 0xEF, 0x53, 0x75, 0x95, 0x9E },
      "EtwAdminlessProvRegHandle", NULL, NULL },
    // 14) SecurityMitigationsProviderGuid
    { { 0x92, 3, 0xE1, 0xFA, 0xAF, 0xF0, 0xC0, 0x4A, 0xB8, 0xFF, 0x9F, 0x4D, 0x92, 0xC, 0x3C, 0xDF },
      "EtwSecurityMitigationsRegHandle", NULL, NULL },
    // from PerfDiagInitialize
    // 15) MS_Kernel_BootDiagnostics_SystemProxy_Provider
    { { 0xB3, 0x4A, 0xFE, 0x7E, 0x0D, 0x99, 0x50, 0x43, 0xA8, 0x78, 0xCD, 0x87, 0x72, 0x88, 0x81, 0x99 },
      "PerfDiagGlobals", NULL, NULL },
    // 16) MS_Kernel_BootDiagnostics_UserProxy_Provider
    { { 0xAB, 0x2C, 0x93, 0x41, 0x12, 0x7E, 0xD6, 0x40, 0xA7, 0x28, 0x62, 0xD3, 0xE, 0x5, 0x45, 0x93 },
      "PerfDiagGlobals[1]", NULL, NULL },
    // 17) MS_Kernel_SecondaryLogonDiagnostics_Proxy_Provider
    { { 0x15, 0x2C, 0x7A, 0xB2, 0xF4, 0x40, 0xA3, 0x4E, 0x96, 0x37, 0x62, 0x8F, 0xC6, 0x12, 0xA1, 0xD0 },
      "PerfDiagGlobals[2]", NULL, NULL },
    // 18) MS_Kernel_ShutdownDiagnostics_Proxy_Provider
    { { 0x10, 0x7A, 0x5C, 0xAD, 8, 0x4E, 0xE1, 0x45, 0x81, 0xB5, 0xCB, 0x5E, 0xB6, 0xEC, 0x89, 0x17 },
     "PerfDiagGlobals[3]", NULL, NULL },
  };
}

void ntoskrnl_hack::dump_etw(PBYTE mz) const
{
  if ( m_CmpTraceRoutine != NULL )
    printf("CmpTraceRoutine: %p\n", PVOID(m_CmpTraceRoutine - mz));
  if ( m_EtwpSessionDemuxObjectType != NULL )
    printf("EtwpSessionDemuxObjectType: %p\n", PVOID(m_EtwpSessionDemuxObjectType - mz));
  for ( auto citer = m_etw_handles.cbegin(); citer != m_etw_handles.cend(); ++citer )
  {
     if ( citer->etw_addr == NULL )
       continue;
     printf("%s: %p\n", citer->name, PVOID(citer->etw_addr - mz));
  }
}

void ntoskrnl_hack::asgn_etw_handle(PBYTE guid_addr, PBYTE value)
{
  if ( guid_addr == NULL )
    return;
  for ( auto iter = m_etw_handles.begin(); iter != m_etw_handles.end(); ++iter )
  {
    if ( iter->aux_addr == guid_addr )
    {
      iter->etw_addr = value;
      return;
    }
  }
}

void ntoskrnl_hack::find_guid_addr(PBYTE mz, etw_descriptor *curr_item)
{
  const one_section *s = m_pe->find_section_by_name(".rdata");
  if ( NULL == s )
    return;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  bm_search srch((const PBYTE)curr_item->guid, sizeof(curr_item->guid));
  while ( curr < end )
  {
    const PBYTE fres = srch.search(curr, end - curr);
    if ( NULL == fres )
      break;
    curr_item->aux_addr = fres;
    return;
  }
  // ok, check .data section too
  s = m_pe->find_section_by_name(".data");
  if ( NULL == s )
    return;
  curr = mz + s->va;
  end = curr + s->size;
  while ( curr < end )
  {
    const PBYTE fres = srch.search(curr, end - curr);
    if ( NULL == fres )
      break;
    curr_item->aux_addr = fres;
    return;
  }
}

int ntoskrnl_hack::hack_etw_handles(PBYTE mz)
{
  for ( auto iter = m_etw_handles.begin(); iter != m_etw_handles.end(); ++iter )
    find_guid_addr(mz, &(*iter));
  // find first non-zero address of found guid
  auto found = std::find_if(m_etw_handles.begin(), m_etw_handles.end(), [](const etw_descriptor &l) -> bool { return l.aux_addr != NULL; });
  if ( found == m_etw_handles.end() )
    return 0;
  // find xref to found guid in INIT section
  const one_section *s = m_pe->find_section_by_name("INIT");
  if ( NULL == s )
    return 0;  
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, found->aux_addr);
  if ( res == NULL )
    return 0;
  // find function start from pdata
  int value = 0;
  PBYTE func_start = find_pdata(res);
  if ( func_start != NULL )
    value += disasm_EtwpInitialize(func_start);
  // try to find PerfDiagInitialize
  found = std::find_if(std::next(m_etw_handles.begin(), 15), m_etw_handles.end(), [](const etw_descriptor &l) -> bool { return l.aux_addr != NULL; });
  if ( found == m_etw_handles.end() )
    return value;
  res = xf.find(mz + s->va, s->size, found->aux_addr);
  if ( res == NULL )
    return value;
  func_start = find_pdata(res);
  if ( func_start != NULL ) 
    value += disasm_EtwpInitialize(func_start);
  return value;
}

int ntoskrnl_hack::disasm_EtwpInitialize(PBYTE psp)
{
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  int res = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("disasm_EtwpInitialize: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( DWORD i = 0; ; i++ )
      {
        if ( !disasm() || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr);
          break;
        }
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          used_regs.add2(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        if ( is_mov_rr(used_regs) )
          continue;
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
          if ( caddr == aux_EtwRegister )
          {
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister
            // NTSTATUS EtwRegister(
            //   x0 - LPCGUID ProviderId,
            //        PETWENABLECALLBACK EnableCallback,
            //        PVOID              CallbackContext,
            //   x3 - PREGHANDLE         RegHandle
            PBYTE guid = (PBYTE)used_regs.get(AD_REG_X0);
            PBYTE value = (PBYTE)used_regs.get(AD_REG_X3);
            if ( guid == NULL || value == NULL )
              continue;
            // check if etw handles located inside .data section
            if ( !in_section(value, ".data") && !in_section(value, "PAGEDATA") )
              continue;
            asgn_etw_handle(guid, value);
            res++;
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
  return res;
}

int ntoskrnl_hack::find_EtwpSessionDemuxObjectType(PBYTE mz)
{
  static const wchar_t *name = L"EtwSessionDemuxEntry";
  // find string in PAGE section
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  size_t b_size = sizeof(wchar_t) * wcslen(name);
  bm_search srch((const PBYTE)name, b_size);
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
    curr = fres + b_size;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  // ok, now find reference in PAGE section
  PBYTE addr = *(founds.cbegin());
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, addr);
  if ( res == NULL )
    return 0;
  return hack_EtwpSessionDemuxObjectType(res);
}

int ntoskrnl_hack::hack_EtwpSessionDemuxObjectType(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 40; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "ALMOSTRO") )
        used_regs.zero(get_reg(0));
      continue;
    }
    // call ObCreateObjectTypeEx
    PBYTE addr = NULL;
    if ( is_bl_jimm(addr) )
    {
      if ( addr == aux_ObCreateObjectTypeEx )
      {
        m_EtwpSessionDemuxObjectType = (PBYTE)used_regs.get(AD_REG_X4);
        break;
      }
    }
  }
  return (m_EtwpSessionDemuxObjectType != NULL);
}

int ntoskrnl_hack::hack_CmpTraceRoutine(PBYTE psp)
{
  statefull_graph<PBYTE, PBYTE> cgraph;
  std::list<std::pair<PBYTE, PBYTE> > addr_list;
  auto curr = std::make_pair(psp, (PBYTE)NULL);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      PBYTE candidate = iter->second;
      int state = (candidate == NULL) ? 0 : 1;
      if ( m_verbose )
        printf("hack_CmpTraceRoutine: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, candidate) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( state && is_add() )
        {
          (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          continue;
        }
        // ldr
        if ( !state && is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, "PAGEDATA") )
            used_regs.zero(get_reg(0));
          else
          {
            candidate = what;
            state = (candidate == NULL) ? 0 : 1;
          }
          continue;
        }
        // br
        if ( state && is_br_reg() )
        {
          PBYTE what = (PBYTE)used_regs.get(get_reg(0));
          if ( what != NULL && in_section(what, "PAGE") )
          {
             cgraph.add(what, candidate);
             continue;
          }
        }
        // mov reg, imm
        if ( state && is_mov_rimm() )
        {
          if ( 0x20000 == (DWORD)m_dis.operands[1].op_imm.bits )
          {
             m_CmpTraceRoutine = candidate;
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
  return (m_CmpTraceRoutine != NULL);
}