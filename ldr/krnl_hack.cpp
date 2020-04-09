#include "stdafx.h"
#include "krnl_hack.h"

void ntoskrnl_hack::zero_data()
{
  // fill auxilary data
  aux_KeAcquireSpinLockRaiseToDpc = NULL;
  if ( m_ed != NULL )
  {
    const export_item *exp = m_ed->find("KeAcquireSpinLockRaiseToDpc");
    if ( exp != NULL )
      aux_KeAcquireSpinLockRaiseToDpc = m_pe->base_addr() + exp->rva;
  }
  // zero output data
  m_ExNPagedLookasideLock = NULL;
  m_ExNPagedLookasideListHead = NULL;
  m_ExPagedLookasideLock = NULL;
  m_ExPagedLookasideListHead = NULL;
}

void ntoskrnl_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_ExNPagedLookasideLock != NULL )
    printf("ExNPagedLookasideLock: %p\n", m_ExNPagedLookasideLock - mz);
  if ( m_ExNPagedLookasideListHead != NULL )
    printf("ExNPagedLookasideListHead: %p\n", m_ExNPagedLookasideListHead - mz);
  if ( m_ExPagedLookasideLock != NULL )
    printf("ExPagedLookasideLock: %p\n", m_ExPagedLookasideLock - mz);
  if ( m_ExPagedLookasideListHead != NULL )
    printf("ExPagedLookasideListHead: %p\n", m_ExPagedLookasideListHead - mz);
}

int ntoskrnl_hack::hack(int verbose)
{
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("ExInitializePagedLookasideList");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next, verbose) )
      res += find_lock_list(next, m_ExPagedLookasideLock, m_ExPagedLookasideListHead, verbose);
  }
  exp = m_ed->find("ExInitializeNPagedLookasideList");
  if ( exp != NULL ) 
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next, verbose) )
      res += find_lock_list(next, m_ExNPagedLookasideLock, m_ExNPagedLookasideListHead, verbose);
  }
  return res;
}

int ntoskrnl_hack::find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list, int verbose)
{
  lock = NULL;
  list = NULL;
  if ( !setup(psp) )
    return 0;
  int state = 0; // 1 - we got lock
  regs_pad used_regs;
  PBYTE tmp;
  for ( DWORD i = 0; i < 200; i++ )
  {
    if ( !disasm(verbose) || is_ret() )
      return 0;
    if ( is_adrp() )
    {
      used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
      continue;
    }
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else if ( state )
      {
        list = what;
        break;
      }
    }
    // check for call
    if ( is_bl_jimm(tmp) )
    {
      if ( tmp == aux_KeAcquireSpinLockRaiseToDpc )
      {
        state = 1;
        lock = (PBYTE)used_regs.get(AD_REG_X0);
      }
    }
  }
  return (lock != NULL) && (list != NULL);
}