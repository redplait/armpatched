#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_vrf()
{
  m_ViDdiInitialized = m_ViVerifierEnabled = NULL;
}

void ntoskrnl_hack::dump_vrf(PBYTE mz) const
{
  if ( m_ViDdiInitialized != NULL )
    printf("ViDdiInitialized: %p\n", PVOID(m_ViDdiInitialized - mz));
  if ( m_ViVerifierEnabled != NULL )
    printf("ViVerifierEnabled: %p\n", PVOID(m_ViVerifierEnabled - mz));
}

int ntoskrnl_hack::disasm_ldr_data(PBYTE psp, PBYTE &res)
{
  if ( !setup(psp) )
    return 0;
  int state = 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 30; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( in_section(what, ".data") )
      {
        res = what;
        return (res != NULL);
      }
    }
  }
  return 0;
}