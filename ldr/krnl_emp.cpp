#include "stdafx.h"
#include "krnl_hack.h"

void ntoskrnl_hack::init_emp()
{
  m_EmpDatabaseLock = m_EmpEntryListHead = NULL;
  m_emp_item_size = 0;
}

void ntoskrnl_hack::dump_emp(PBYTE mz) const
{
  if ( m_EmpDatabaseLock != NULL )
    printf("EmpDatabaseLock: %p\n", PVOID(m_EmpDatabaseLock - mz));
  if ( m_EmpEntryListHead != NULL )
    printf("EmpEntryListHead: %p\n", PVOID(m_EmpEntryListHead - mz));
  if ( m_emp_item_size )
    printf("emp item size: %X\n", m_emp_item_size);
}

int ntoskrnl_hack::find_emp_list(PBYTE psp)
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
       if ( !in_section(what, ".data") )
       {
          used_regs.zero(get_reg(0));
          continue;
       }
       m_EmpEntryListHead = what;
       break;
    }
  }
  return (m_EmpEntryListHead != NULL);
}

int ntoskrnl_hack::hack_emp(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0;
  PBYTE call_addr = NULL;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_mov_rimm() )
    {
       used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
       continue;
    }
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( caddr == aux_ExAcquirePushLockExclusiveEx )
      {
        m_EmpDatabaseLock = (PBYTE)used_regs.get(AD_REG_X0);
        state = 1;
        continue;
      }
      if ( caddr == aux_ExAllocatePoolWithTag )
      {
        if ( 1 == state )
        {
          m_emp_item_size = (DWORD)used_regs.get(AD_REG_X1);
          state = 2;
        }
        continue;
      }
      if ( caddr == aux_memset )
      {
        state = 3;
        continue;
      }
      if ( 3 == state )
      {
        call_addr = caddr;
        break;
      }
    }
    if ( is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, ".data") )
       {
          used_regs.zero(get_reg(0));
          continue;
       }
    }
  }
  if ( call_addr != NULL )
    find_emp_list(call_addr);
  return (m_EmpDatabaseLock != NULL) && (m_EmpEntryListHead != NULL);
}