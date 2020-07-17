#include "stdafx.h"
#include "combase_hack.h"

void combase_hack::zero_data()
{
  m_gfEnableTracing = NULL;
}

void combase_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_gfEnableTracing != NULL )
    printf("gfEnableTracing: %p\n", PVOID(m_gfEnableTracing - mz));
}

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