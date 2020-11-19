#include "stdafx.h"
#include "krnl_hack.h"

void ntoskrnl_hack::init_bugcheck_data()
{
  m_KeBugCheckCallbackLock = m_KeBugCheckCallbackListHead = NULL;
  m_KeBugCheckReasonCallbackListHead = m_KeBugCheckAddRemovePagesCallbackListHead = NULL;
  m_IopNotifyLastChanceShutdownQueueHead = m_IopNotifyShutdownQueueHead = NULL;
}

void ntoskrnl_hack::dump_bugcheck_data(PBYTE mz) const
{
  if ( m_KeBugCheckCallbackLock != NULL )
    printf("KeBugCheckCallbackLock: %p\n", PVOID(m_KeBugCheckCallbackLock - mz));
  if ( m_KeBugCheckCallbackListHead != NULL )
    printf("KeBugCheckCallbackListHead: %p\n", PVOID(m_KeBugCheckCallbackListHead - mz));
  if ( m_KeBugCheckReasonCallbackListHead != NULL )
    printf("KeBugCheckReasonCallbackListHead: %p\n", PVOID(m_KeBugCheckReasonCallbackListHead - mz));
  if ( m_KeBugCheckAddRemovePagesCallbackListHead != NULL )
    printf("KeBugCheckAddRemovePagesCallbackListHead: %p\n", PVOID(m_KeBugCheckAddRemovePagesCallbackListHead - mz));
  if ( m_IopNotifyLastChanceShutdownQueueHead != NULL )
    printf("IopNotifyLastChanceShutdownQueueHead: %p\n", PVOID(m_IopNotifyLastChanceShutdownQueueHead - mz));
  if ( m_IopNotifyShutdownQueueHead != NULL )
    printf("IopNotifyShutdownQueueHead: %p\n", PVOID(m_IopNotifyShutdownQueueHead - mz));
}

int ntoskrnl_hack::find_KxAcquireSpinLock(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  int state = 0; // 0 - wait for KeAcquireSpinLockRaiseToDpc
  for ( DWORD i = 0; i < 50; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    PBYTE addr = NULL;
    if ( is_bl_jimm(addr) )
    {
      if ( addr == aux_KeAcquireSpinLockRaiseToDpc )
      {
        state = 1;
        continue;
      }
      if ( state )
      {
        aux_KxAcquireSpinLock = addr;
        break;
      }
    }
  }
  return (aux_KxAcquireSpinLock != NULL);
}

int ntoskrnl_hack::hack_bugcheck_reason(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for KeAcquireSpinLockAtDpcLevel
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      if ( state )
      {
        // first KeBugCheckReasonCallbackListHead
        if ( m_KeBugCheckReasonCallbackListHead == NULL )
          m_KeBugCheckReasonCallbackListHead = what;
        else {
          m_KeBugCheckAddRemovePagesCallbackListHead = what;
          break;
        }
      }
      continue;
    }
    PBYTE addr = NULL;
    if ( is_bl_jimm(addr) )
    {
      if ( (addr == aux_KeAcquireSpinLockAtDpcLevel) ||
           (addr == aux_KxAcquireSpinLock)
         )
        state = 1;
    }
  }
  return (m_KeBugCheckReasonCallbackListHead != NULL);
}

int ntoskrnl_hack::hack_bugcheck(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for KeAcquireSpinLockAtDpcLevel
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      if ( state )
      {
        m_KeBugCheckCallbackListHead = what;
        break;
      }
      continue;
    }
    // call
    PBYTE addr = NULL;
    if ( is_bl_jimm(addr) )
    {
      if ( (addr == aux_KeAcquireSpinLockAtDpcLevel) ||
           (addr == aux_KxAcquireSpinLock)
         )
      {
        state = 1;
        m_KeBugCheckCallbackLock = (PBYTE)used_regs.get(AD_REG_X0);
      }
    }
  }
  return (m_KeBugCheckCallbackLock != NULL) && (m_KeBugCheckCallbackListHead != NULL);
}

// common function to find xxQueueHead - first data loaded after ObfReferenceObject
int ntoskrnl_hack::disasm_qhead(PBYTE psp, PBYTE &out_res)
{
  traverse_simple_state_graph(psp, [&](int *state, regs_pad *used_regs) -> int
   {
     // call
     PBYTE addr = NULL;
     if ( is_bl_jimm(addr) )
     {
       if ( addr == aux_ObfReferenceObject )
       {
         *state = 1;
         return 0;
       }
       return 0;
     }
     if ( *state && is_add() )
     {
        PBYTE what = (PBYTE)used_regs->add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
        if ( !in_section(what, ".data") )
          return 0;
        out_res = what;
        return 1;
     }
     return 0;
   }, "disasm_qhead");
  return (out_res != NULL);
}