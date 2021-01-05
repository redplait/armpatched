#include "stdafx.h"
#include "afd_hack.h"
#include "bm_search.h"
#include "cf_graph.h"

void afd_hack::zero_data()
{
  m_wsk_size = 0;
  m_AfdWskClientSpinLock = m_AfdWskClientListHead = NULL;
}

void afd_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_AfdWskClientSpinLock != NULL )
    printf("AfdWskClientSpinLock: %p\n", PVOID(m_AfdWskClientSpinLock - mz));
  if ( m_AfdWskClientListHead != NULL )
    printf("AfdWskClientListHead: %p\n", PVOID(m_AfdWskClientListHead - mz));
  if ( m_wsk_size )
    printf("wsk item size: %X\n", m_wsk_size);
}

int afd_hack::hack(int verbose)
{
  m_verbose = verbose;
  PBYTE mz = m_pe->base_addr();
  // try search tag in .text section
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
  const DWORD sign = 0x43444661; // allocation tag
  bm_search srch((const PBYTE)&sign, sizeof(sign));
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
    curr = fres + sizeof(sign);
  }
  if ( founds.empty() )
    return 0;
  for ( auto citer = founds.cbegin(); citer != founds.cend(); ++citer )
  {
    PBYTE func = find_pdata(*citer);
    if ( NULL == func )
      continue;
#ifdef _DEBUG
    printf("afd_hack: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    // state: 0 - wait for our tag
    //        1 - wait for call to alloc
    //        2 - wait for lock call
    traverse_simple_state_graph(func, [&](int *state, regs_pad *used_regs) -> int
    {
      // check loading of tag
      if ( !*state && is_ldr_off() )
      {
        DWORD tmp = *(PDWORD)m_dis.operands[1].op_imm.bits;
        if ( tmp == sign )
          *state = 1;
        return 0;
      }
      // just store all mov reg, imm
      if ( is_mov_rimm() )
      {
        used_regs->adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
        return 0;
      }
      if ( is_add() )
      {
        PBYTE what = (PBYTE)used_regs->add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
        // check what state we have
        if ( *state == 3 && in_section(what, ".data") )
        {
          m_AfdWskClientListHead = what;
          return 1;
        }
      }
      // ldar
      if ( is_ldar(used_regs) )
        return 0;
      // bl reg - usually call [IAT]
      if ( is_bl_reg() )
      {
        PBYTE what = (PBYTE)used_regs->get(get_reg(0));
        if ( is_iat_func(what, "ExAllocatePoolWithTag") ||
             is_iat_func(what, "ExAllocatePool2")
           )
        {
          *state = 2;
          m_wsk_size = used_regs->get(AD_REG_X1);
          return 0;
        }
        // if state 2 - check for KeAcquireInStackQueuedSpinLock
        if ( *state == 2 && is_iat_func(what, "KeAcquireInStackQueuedSpinLock") )
        {
          what = (PBYTE)used_regs->get(AD_REG_X0);
          if ( in_section(what, ".data") )
            m_AfdWskClientSpinLock = what;
          *state = 3;
        }
      }
      return 0;
    }, "disasm_AfdWskNotifyAttachClient");
    if ( is_wsk_ok() )
      return 1;
  }
  return 0;
}