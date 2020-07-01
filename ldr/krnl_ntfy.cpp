#include "stdafx.h"
#include "krnl_hack.h"

int ntoskrnl_hack::hack_cm_cbs(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for ExAcquirePushLockExclusiveEx
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( caddr == aux_ExAcquirePushLockExclusiveEx )
      {
        m_CmpCallbackListLock = (PBYTE)used_regs.get(AD_REG_X0);
        state = 1;
        continue;
      } else
        break;
    }
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else if ( state == 1 )
      {
        m_CallbackListHead = what;
        break;
      }
    }
  }
  return (m_CmpCallbackListLock != NULL) && (m_CallbackListHead != NULL);
}

int ntoskrnl_hack::resolve_notify(PBYTE psp, PBYTE &list, PBYTE &count)
{
  count = NULL;
  list = NULL;
  if ( !setup(psp) )
    return 0;
  int state = 0; // 0 - wait for ExAllocateCallBack
                 // 1 - get list
                 // 2 - wait for ExCompareExchangeCallBack
                 // 3 - add magic to get count
  regs_pad used_regs;
  for ( DWORD i = 0; i < 200; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    // check for call
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( !state && (caddr == aux_ExAllocateCallBack) )
        state = 1;
      else if ( (2 == state) && (caddr == aux_ExCompareExchangeCallBack) )
        state = 3;
    }
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( 1 == state )
      {
        if ( !in_section(what, ".data") )
          used_regs.zero(get_reg(0));
        else {
          list = what;
          state = 2;
        }      
      } else if ( 3 == state )
      {
        if ( !in_section(what, "PAGEDATA") )
          used_regs.zero(get_reg(0));
        else
          state = 4;
      } else if (4 == state)
      {
        count = what;
        break;
      }
    }
  }
  return (list != NULL) && (count != NULL);
}
