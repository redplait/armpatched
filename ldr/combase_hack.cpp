#include "stdafx.h"
#include "cf_graph.h"
#include "combase_hack.h"

void combase_hack::zero_data()
{
  m_gfEnableTracing = NULL;
  tlg_PoFAggregate = NULL;
}

void combase_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_gfEnableTracing != NULL )
    printf("gfEnableTracing: %p\n", PVOID(m_gfEnableTracing - mz));
  if ( tlg_PoFAggregate != NULL )
    printf("tlg_PoFAggregate: %p\n", PVOID(tlg_PoFAggregate - mz));
  if ( !tlg_CombaseTraceLoggingProviderProv.empty() )
  {
    printf("tlg_CombaseTraceLoggingProviderProv:\n");
    for ( auto citer = tlg_CombaseTraceLoggingProviderProv.cbegin(); citer != tlg_CombaseTraceLoggingProviderProv.cend(); ++citer )
      printf(" %p\n", PVOID(*citer - mz));
  }
  if ( !m_wpp.empty() )
  {
    printf("WPP_GLOBAL_Controls:\n");
    for ( auto citer = m_wpp.cbegin(); citer != m_wpp.cend(); ++citer )
      printf(" %p\n", PVOID(*citer - mz));
  }
}

#include <initguid.h>
DEFINE_GUID( PoFAggregate_GUID, 0xC7E09E2A, 0xC663, 0x5399, 0xAF, 0x79, 0x2F, 0xCC, 0xD3, 0x21, 0xD1, 0x9A);
DEFINE_GUID( CombaseTraceLoggingProviderProv_GUID, 0x1AFF6089, 0xE863, 0x4D36, 0xBD, 0xFD, 0x35, 0x81, 0xF0, 0x74, 0x40, 0xBE);

int combase_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("RoGetAgileReference");
  if ( exp != NULL )
    res += resolve_gfEnableTracing(mz + exp->rva);
  res += find_tlg_by_guid((const PBYTE)&PoFAggregate_GUID, mz, tlg_PoFAggregate);
  res += find_tlgs_by_guid((const PBYTE)&CombaseTraceLoggingProviderProv_GUID, mz, tlg_CombaseTraceLoggingProviderProv);
  res += find_wpps(mz, m_wpp);
  return res;
}

int combase_hack::resolve_gfEnableTracing(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 20; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_ldr() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( in_section(what, ".data") )
         m_gfEnableTracing = what;
       break;
    }
  }
  return (m_gfEnableTracing != NULL);
}
