#include "stdafx.h"
#include "ndis_hack.h"

void ndis_hack::zero_data()
{
  m_ndisProtocolListLock = m_ndisProtocolList = NULL;
  m_ndisFilterDriverListLock = m_ndisFilterDriverList = NULL;
  m_ndisMiniDriverListLock = m_ndisMiniDriverList = NULL;
  NDIS_M_DRIVER_BLOCK_size = NDIS_PROTOCOL_BLOCK_size = 0;
}

void ndis_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_ndisProtocolListLock != NULL )
    printf("ndisProtocolListLock: %p\n", PVOID(m_ndisProtocolListLock - mz));
  if ( m_ndisProtocolList != NULL )
    printf("ndisProtocolList: %p\n", PVOID(m_ndisProtocolList - mz));
  if ( NDIS_PROTOCOL_BLOCK_size )
    printf("NDIS_PROTOCOL_BLOCK size: %X\n", NDIS_PROTOCOL_BLOCK_size);

  if ( m_ndisFilterDriverListLock != NULL )
    printf("ndisFilterDriverListLock: %p\n", PVOID(m_ndisFilterDriverListLock - mz));
  if ( m_ndisFilterDriverList != NULL )
    printf("ndisFilterDriverList: %p\n", PVOID(m_ndisFilterDriverList - mz));

  if ( m_ndisMiniDriverListLock != NULL )
    printf("ndisMiniDriverListLock: %p\n", PVOID(m_ndisMiniDriverListLock - mz));
  if ( m_ndisMiniDriverList != NULL )
    printf("ndisMiniDriverList: %p\n", PVOID(m_ndisMiniDriverList - mz));
  if ( NDIS_M_DRIVER_BLOCK_size )
    printf("NDIS_M_DRIVER_BLOCK size: %X\n", NDIS_M_DRIVER_BLOCK_size);
}

int drv_hack::is_inside_IAT(PBYTE psp) const
{
  if ( NULL == m_iat )
    return 0;
  ptrdiff_t off = psp - m_pe->base_addr();
  if ( (off >= m_iat->iat_rva) &&
       (off < (m_iat->iat_rva + m_iat->iat_size))
     )
    return 1;
  return 0;
}

int drv_hack::is_iat_func(PBYTE psp, const char *name) const
{
  if ( NULL == m_iat )
    return 0;
  ptrdiff_t off = psp - m_pe->base_addr();
  if ( (off >= m_iat->iat_rva) &&
       (off < (m_iat->iat_rva + m_iat->iat_size))
     )
  {
    size_t index = (off - m_iat->iat_rva) / 8;
    if ( m_iat->iat[index].name != NULL && !strcmp(m_iat->iat[index].name, name) )
      return 1;
  }
  return 0;
}

int ndis_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();

  const export_item *exp = m_ed->find("NdisDeregisterProtocolDriver");
  if ( exp != NULL )
  {
    std::set<PBYTE> calls;
    collect_calls(mz + exp->rva, calls, "PAGENPNP");
    for ( auto citer = calls.cbegin(); citer != calls.cend(); ++citer )
    {
      if ( verbose )
        printf("Try function at %p\n", *citer);
      if ( hack_lock_list(*citer, 100, m_ndisProtocolListLock, m_ndisProtocolList) )
      {
        res++;
        break;
      }
    }
  }
  if ( m_ndisProtocolList != NULL )
  {
    exp = m_ed->find("NdisRegisterProtocolDriver");
    if ( exp != NULL )
      res += hack_alloc(mz + exp->rva, 0x6270444E, NDIS_PROTOCOL_BLOCK_size);
  }

  exp = m_ed->find("NdisFRegisterFilterDriver");
  if ( exp != NULL )
    res += hack_lock_list(mz + exp->rva, 300, m_ndisFilterDriverListLock, m_ndisFilterDriverList);

  exp = m_ed->find("NdisMRegisterMiniportDriver");
  if ( exp != NULL )
  {
    std::set<PBYTE> calls;
    collect_calls(mz + exp->rva, calls, ".text");
    for ( auto citer = calls.cbegin(); citer != calls.cend(); ++citer )
    {
      if ( verbose )
        printf("Try function at %p\n", *citer);
      if ( hack_lock_list(*citer, 200, m_ndisMiniDriverListLock, m_ndisMiniDriverList) )
      {
        res++;
        res += hack_alloc_ext(*citer, NDIS_M_DRIVER_BLOCK_size);
        break;
      }
    }
  }

  return res;
}

void ndis_hack::collect_calls(PBYTE psp, std::set<PBYTE> &calls, const char *s_name)
{
  if ( !setup(psp) )
    return;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm() || is_ret() )
      return;
    PBYTE addr;
    if ( is_b_jimm(addr) )
    {
      if ( in_section(addr, s_name) )
        calls.insert(addr);
      break;
    }
    if ( is_bl_jimm(addr) )
    {
      if ( in_section(addr, s_name) )
        calls.insert(addr);
    }
  }
}

int ndis_hack::hack_lock_list(PBYTE psp, DWORD num, PBYTE &lock, PBYTE &list)
{
  lock = NULL;
  list = NULL;
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - expect KeAcquireSpinLockRaiseToDpc call from IAT
                 // 1 - expect list loading
  for ( DWORD i = 0; i < num; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    PBYTE addr;
    if ( is_b_jimm(addr) )
      break;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_ldar(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !state )
      {
        if ( !is_inside_IAT(what) )
        {
          if ( !in_section(what, ".data") )
            used_regs.zero(get_reg(0));
        }
      }
    }
    // call reg
    if ( is_bl_reg() )
    {
      if ( state )
        break;
      PBYTE what = (PBYTE)used_regs.get(get_reg(0));
      if ( is_iat_func(what, "KeAcquireSpinLockRaiseToDpc") )
      {
        state = 1;
        lock = (PBYTE)used_regs.get(AD_REG_X0);
      }
    }
    if ( state && is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( in_section(what, ".data") )
      {
        list = what;
        break;
      }
    }
  }
  return (lock != NULL) && (list != NULL);
}

// ExAllocatePool2 - x1 size x2 - tag
// ExAllocatePoolWithTag - same as above
int ndis_hack::hack_alloc(PBYTE psp, DWORD tag, DWORD &out_size)
{
  regs_pad used_regs;
  if ( !setup(psp) )
    return 0;
  int state = 0;
  for ( DWORD i = 0; i < 200; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    PBYTE addr;
    if ( is_b_jimm(addr) )
      break;
    if ( is_adrp(used_regs) )
    {
      state = 1;
      continue;
    }
    // ldr reg, [const pool]
    if ( is_ldr_off() ) 
    {
      PDWORD what = (PDWORD)m_dis.operands[1].op_imm.bits;
      if ( in_section((PBYTE)what, ".text") )
      {
        DWORD value = *what;
        used_regs.adrp(get_reg(0), value);
      }
      continue;
    }
    if ( is_add() )
    {
      int r0 = get_reg(0);
      int r1 = get_reg(1);
      if ( !state )
      {
        used_regs.adrp(r0, m_dis.operands[2].op_imm.bits);        
        continue;
      }
      used_regs.add(r0, r1, m_dis.operands[2].op_imm.bits);
      state = 0;
      continue;
    }
    if ( is_ldar(used_regs) )
      continue;
    if ( is_mov_rr(used_regs) )
      continue;
    if ( is_bl_reg() )
    {
      PBYTE what = (PBYTE)used_regs.get(get_reg(0));
      if ( is_iat_func(what, "ExAllocatePoolWithTag") ||
           is_iat_func(what, "ExAllocatePool2")
         )
      {
        if ( tag != used_regs.get(AD_REG_X2) )
          continue;
        out_size = used_regs.get(AD_REG_X1);
        break;
      }
    }
  }
  return (out_size != 0);
}

// IoAllocateDriverObjectExtension: x1 - ClientIdentificationAddress (can be used as tag), x2 - size
int ndis_hack::hack_alloc_ext(PBYTE psp, DWORD &out_size)
{
  regs_pad used_regs;
  if ( !setup(psp) )
    return 0;
  int state = 0;
  for ( DWORD i = 0; i < 200; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    PBYTE addr;
    if ( is_b_jimm(addr) )
      break;
    if ( is_adrp(used_regs) )
    {
      state = 1;
      continue;
    }
    if ( is_add() )
    {
      int r0 = get_reg(0);
      int r1 = get_reg(1);
      if ( !state )
      {
        used_regs.adrp(r0, m_dis.operands[2].op_imm.bits);        
        continue;
      }
      used_regs.add(r0, r1, m_dis.operands[2].op_imm.bits);
      state = 0;
      continue;
    }
    if ( is_ldar(used_regs) )
      continue;
    if ( is_mov_rr(used_regs) )
      continue;
    if ( is_bl_reg() )
    {
      PBYTE what = (PBYTE)used_regs.get(get_reg(0));
      if ( is_iat_func(what, "IoAllocateDriverObjectExtension") )
      {
        out_size = used_regs.get(AD_REG_X2);
        break;
      }
    }
  }
  return (out_size != 0);
}