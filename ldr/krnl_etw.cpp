#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::init_etw()
{
  m_CmpTraceRoutine = NULL;
  m_EtwpRegistrationObjectType = m_EtwpSessionDemuxObjectType = NULL;
  m_tlg_handles = {
    { { 0xA7, 0xC5, 0x51, 0x0F, 0x76, 0x0E, 0xA5, 0x47, 0xBE, 0xDE, 0x7C, 0xF6, 0x2C, 0x58, 0x22, 0xF6 },
      "Microsoft.Windows.Kernel.HAL", NULL, ".data" },
    { { 0x76, 0xBA, 0x04, 0x1D, 0x3E, 0x09, 0x74, 0xE3, 0xDB, 0x19, 0x40, 0xB9, 0x7D, 0x54, 0xED, 0xCB },
      "Microsoft.Windows.FileSystem.Cache", NULL, ".data" },
    { { 0x18, 0xF4, 0xEA, 0xE9, 0x07, 0x0C, 0x4C, 0x46, 0xAD, 0x14, 0xA7, 0xF3, 0x53, 0x34, 0x9A, 0x00 },
      "Microsoft.Windows.Kernel.Registry", NULL, ".data" },
    { { 0x26, 0x34, 0xE8, 0xF7, 0x81, 0x2B, 0xF9, 0x58, 0xC5, 0xD4, 0xF2, 0xDB, 0x6D, 0x0A, 0xD4, 0x73 },
      "Microsoft.Windows.Kernel.FeatureConfigurationManager", NULL, ".data" },
    { { 0xCC, 0x9E, 0x2D, 0x25, 0x9F, 0x1C, 0x17, 0x49, 0x87, 0x60, 0xF8, 0x72, 0xA8, 0x3B, 0xF0, 0x18 },
      "Microsoft.Windows.Containers.RegistryVirtualization", NULL, ".data" },
    { { 0xB2, 0x3A, 0xA3, 0x73, 0x66, 0x19, 0x99, 0x49, 0x8A, 0xDD, 0x86, 0x8C, 0x41, 0x41, 0x52, 0x69 },
      "IumTelemetryProvider", NULL, ".data" },
    { { 0x6B, 0xE8, 0x1E, 0xA5, 0xA5, 0x8E, 0x4C, 0x45, 0x9A, 0x7D, 0x37, 0xB6, 0x65, 0x5A, 0x53, 0x5D },
      "Microsoft.Windows.Kernel.Dump", NULL, ".data" },
    { { 0xC5, 0x6F, 0xD1, 0xA4, 0xCF, 0xD1, 0x72, 0x4D, 0xA0, 0x55, 0x25, 0xF3, 0xEB, 0x02, 0xA7, 0x0E },
      "Microsoft.Windows.Kernel.LiveDump", NULL, ".data" },
    { { 0x7B, 0xF3, 0xFD, 0xA9, 0x2D, 0xD7, 0x51, 0x40, 0xA3, 0xCD, 0xD4, 0x22, 0x10, 0x3C, 0xE0, 0x79 },
      "Microsoft.Windows.Kernel.SysEnv", NULL, ".data" },
    { { 0xFF, 0xE9, 0xBD, 0xC8, 0x1F, 0xF3, 0xDC, 0x59, 0x6C, 0x27, 0xCA, 0x37, 0xC5, 0x16, 0xAD, 0xA5 },
      "Microsoft.Windows.Kernel.DeviceConfig", NULL, ".data" },
    { { 0xBB, 0xBB, 0x0E, 0x6C, 0x92, 0xC2, 0x7D, 0x45, 0x96, 0x75, 0xDF, 0xCC, 0x1C, 0x0D, 0x58, 0xB0 },
      "Microsoft.Windows.Kernel.PnP", NULL, ".data" },
    { { 0xC3, 0x37, 0x1C, 0x06, 0x63, 0x13, 0x1B, 0x5C, 0xB8, 0xED, 0xF3, 0xD8, 0xF7, 0x46, 0x33, 0xCE },
      "Microsoft.Windows.Kernel.Kernel", NULL, ".data" },
    { { 0x9C, 0x8B, 0x9E, 0x7E, 0x6C, 0x40, 0x73, 0x5D, 0xE5, 0x66, 0x0F, 0x50, 0xEA, 0x3A, 0xDE, 0x3E },
      "Microsoft-Windows-Kernel-Mm", NULL, ".data" },
    { { 0xD1, 0x12, 0x94, 0xF3, 0xFD, 0xC9, 0x79, 0x5E, 0x8A, 0x82, 0x9C, 0x9C, 0xBD, 0x8C, 0xA8, 0x09 },
      "Microsoft.Windows.Kernel.ObjectManager", NULL, ".data" },
    { { 0xA1, 0xA7, 0xBC, 0x63, 0xEC, 0x77, 0xA7, 0x4E, 0x95, 0xD0, 0x98, 0xD3, 0xF0, 0xC0, 0xEB, 0xF7 },
      "Microsoft.Windows.Kernel.Power", NULL, ".data" },
    { { 0x7B, 0x4B, 0xD0, 0x57, 0x0A, 0x55, 0xA2, 0x49, 0xAB, 0xCC, 0xA7, 0xFA, 0x15, 0x59, 0x8A, 0x30 },
      "Microsoft.Windows.Kernel.Power.DiagFxAccounting", NULL, ".data" },
    { { 0x27, 0xD7, 0x2E, 0x0D, 0xA0, 0x38, 0x2B, 0x4B, 0x9F, 0x7E, 0xEC, 0x79, 0xB5, 0xEC, 0x4A, 0xA5 },
      "Microsoft.Windows.Kernel.Power.DirectedDrips", NULL, "PAGEDATA" },
    { { 0x99, 0xF8, 0x0B, 0x05, 0x06, 0xDA, 0x52, 0x48, 0xA6, 0x3A, 0x81, 0xE6, 0xB9, 0xA1, 0xC7, 0x4F },
      "Microsoft.Windows.Kernel.Power.PowerTransitions", NULL, ".data" },
    { { 0x4D, 0x3E, 0x75, 0x5E, 0x0D, 0x2B, 0x51, 0x44, 0xB8, 0xF9, 0x0F, 0x12, 0x53, 0xCA, 0x0B, 0x44 },
      "Microsoft.Windows.Kernel.Ttm", NULL, "PAGEDATA" },
    { { 0xD8, 0x73, 0x96, 0xC5, 0x96, 0xB7, 0xDF, 0x58, 0xFB, 0xF8, 0xA7, 0x0B, 0xAD, 0x65, 0x6D, 0xCA },
      "Microsoft.Windows.Kernel.ProcessSubsystem", NULL, ".data" },
    { { 0xF4, 0xFD, 0xA8, 0x27, 0x77, 0x9B, 0x5B, 0x57, 0xBE, 0x3B, 0xE7, 0x16, 0x3E, 0xF1, 0x59, 0xBB },
      "Microsoft.Windows.Security.Capabilities", NULL, ".data" },
    { { 0x38, 0x9A, 0xA6, 0x09, 0x80, 0x26, 0xFA, 0x4B, 0xAD, 0x01, 0x79, 0x2A, 0xD6, 0x3A, 0x4F, 0xF2 },
      "Microsoft.Windows.Kernel.Security", NULL, ".data" },
    { { 0xE0, 0xD4, 0xFB, 0xB7, 0x8F, 0xFA, 0x58, 0x4C, 0xB0, 0xFB, 0x3C, 0xC2, 0x27, 0xB8, 0x6E, 0xD6 },
      "Microsoft-Windows-Kernel-Vm", NULL, "ALMOSTRO" },
    { { 0x1C, 0x52, 0x14, 0x76, 0x0B, 0x4D, 0x41, 0x43, 0xBF, 0xC9, 0x87, 0x30, 0x82, 0xC0, 0xF1, 0xD3 },
      "KernelGeneral", NULL, ".data" },
    { { 0x94, 0xFF, 0x39, 0x28, 0x12, 0x8F, 0x1B, 0x4E, 0x82, 0xE3, 0xAF, 0x7A, 0xF7, 0x7A, 0x45, 0x0F },
      "KernelProcess", NULL, ".data" },
    { { 0xC9, 0xB8, 0xD9, 0x1D, 0x78, 0xE0, 0x75, 0x40, 0xB9, 0xDE, 0x4E, 0x51, 0x25, 0x07, 0x1A, 0x18 },
      "MSTelCov", NULL, ".data" },
    { { 0x75, 0x6A, 0xB7, 0x23, 0x4F, 0xCE, 0xEF, 0x56, 0xF9, 0x03, 0xC3, 0xA2, 0xD6, 0xAE, 0x3F, 0x6B },
      "Microsoft.Windows.Kernel.BootEnvironment", NULL, ".data" },
    { { 0x3C, 0xA5, 0x44, 0x89, 0x61, 0xA5, 0x53, 0x4E, 0xA0, 0xC6, 0xD5, 0x65, 0x41, 0x47, 0x45, 0xFC },
      "KernelExecutive", NULL, ".data" },
    { { 0x13, 0xCC, 0x3F, 0x70, 0x6F, 0xB6, 0x68, 0x58, 0xDD, 0xD9, 0xE2, 0xDB, 0x7F, 0x38, 0x1F, 0xFB }, 
      "Microsoft.Windows.TlgAggregateInternal", NULL, ".data" },
  };
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
  // zero mcgen data
  MS_KernelCc_Provider_Context =
  MS_StorageTiering_Provider_Context =
  IoMgrProvider_Context =
  MS_KernelPnP_Provider_Context = NULL;
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
  for ( auto tlg_citer = m_tlg_handles.cbegin(); tlg_citer != m_tlg_handles.cend(); ++tlg_citer )
  {
     if (tlg_citer->etw_addr == NULL )
       continue;
     printf("tlg %s: %p\n", tlg_citer->name, PVOID(tlg_citer->etw_addr - mz));
  }
  // mcgen stuff
  if ( MS_KernelCc_Provider_Context != NULL )
    printf("MS_KernelCc_Provider_Context: %p\n", PVOID(MS_KernelCc_Provider_Context - mz));
  if ( MS_StorageTiering_Provider_Context != NULL )
    printf("MS_StorageTiering_Provider_Context: %p\n", PVOID(MS_StorageTiering_Provider_Context - mz));
  if ( IoMgrProvider_Context != NULL )
    printf("IoMgrProvider_Context: %p\n", PVOID(IoMgrProvider_Context - mz));
  if ( MS_KernelPnP_Provider_Context != NULL )
    printf("MS_KernelPnP_Provider_Context: %p\n", PVOID(MS_KernelPnP_Provider_Context - mz));
}

static const BYTE s_KernelCc_Provider[16] = { 0xF1, 0x4B, 0xD3, 0xA2, 0xAB, 0x70, 0x21, 0x5B, 0xC8, 0x19, 0x5A, 0x0D, 0xD4, 0x27, 0x48, 0xFD };
static const BYTE s_StorageTiering_Provider[16] = { 0xFC, 0x55, 0x0C, 0x99, 0x62, 0x26, 0xF6, 0x47, 0xB7, 0xD7, 0xEB, 0x3C, 0x02, 0x7C, 0xB1, 0x3F };
static const BYTE s_IoMgrProvider[16] = { 0x86, 0xF5, 0xF1, 0xAB, 0x50, 0x2E, 0xA8, 0x4B, 0x92, 0x8D, 0x49, 0x04, 0x4E, 0x6F, 0x0D, 0xB7 };
static const BYTE s_KernelPnP_Provider[16] = { 0x39, 0x5A, 0x20, 0x9C, 0x50, 0x12, 0x7D, 0x48, 0xAB, 0xD7, 0xE8, 0x31, 0xC6, 0x29, 0x05, 0x39 };

int ntoskrnl_hack::hack_mcgen_contexts(PBYTE mz)
{
  int res = find_Provider_Context((const PBYTE)s_KernelCc_Provider, ".text", mz, MS_KernelCc_Provider_Context);
  res += find_Provider_Context((const PBYTE)s_StorageTiering_Provider, "PAGE", mz, MS_StorageTiering_Provider_Context);
  res += find_Provider_Context((const PBYTE)s_IoMgrProvider, "INIT", mz, IoMgrProvider_Context);
  res += find_Provider_Context((const PBYTE)s_KernelPnP_Provider, "INIT", mz, MS_KernelPnP_Provider_Context);
  return res;
}

int ntoskrnl_hack::hack_tlg_handles(PBYTE mz)
{
  int res = 0;
  for ( auto iter = m_tlg_handles.begin(); iter != m_tlg_handles.end(); ++iter )
  {
    std::list<PBYTE> aux_list;
    if ( !find_tlgs_guid4(iter->guid, mz, aux_list) )
      continue;
    for ( auto citer = aux_list.cbegin(); citer != aux_list.cend(); ++citer )
    {
      if ( find_tlg_ref(*citer + 16, mz, iter->section_name, iter->etw_addr) )
      {
        res++;
        break;
      }
    }
  }
  return res;
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
             cgraph.add(what, candidate);
          break;
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