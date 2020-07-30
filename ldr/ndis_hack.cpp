#include "stdafx.h"
#include "ndis_hack.h"
#include "cf_graph.h"

void ndis_hack::zero_data()
{
  m_ndisProtocolListLock = m_ndisProtocolList = NULL;
  m_ndisFilterDriverListLock = m_ndisFilterDriverList = NULL;
  m_ndisMiniDriverListLock = m_ndisMiniDriverList = NULL;
  m_ndisMiniportListLock = m_ndisMiniportList = NULL;
  m_ndisGlobalOpenListLock = m_ndisGlobalOpenList = NULL;
  NDIS_M_DRIVER_BLOCK_size = NDIS_PROTOCOL_BLOCK_size = 0;
  m_NextGlobalMiniport = 0;
  tlg_TelemetryAssert = tlg_TelemetryAssertDiagTrack = tlg_TelemetryAssertDiagTrack_KM = 0;
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

  if ( m_ndisMiniportListLock != NULL )
    printf("ndisMiniportListLock: %p\n", PVOID(m_ndisMiniportListLock - mz));
  if ( m_ndisMiniportList != NULL )
    printf("ndisMiniportList: %p\n", PVOID(m_ndisMiniportList - mz));
  if ( m_NextGlobalMiniport )
    printf("NDIS_MINIPORT_BLOCK.NextGlobalMiniport: %X\n", m_NextGlobalMiniport);

  if ( m_ndisGlobalOpenListLock != NULL )
    printf("ndisGlobalOpenListLock: %p\n", PVOID(m_ndisGlobalOpenListLock - mz));
  if ( m_ndisGlobalOpenList != NULL )
    printf("ndisGlobalOpenList: %p\n", PVOID(m_ndisGlobalOpenList - mz));

  if ( tlg_TelemetryAssert != NULL )
    printf("TelemetryAssert: %p\n", PVOID(tlg_TelemetryAssert - mz));
  if ( tlg_TelemetryAssertDiagTrack != NULL )
    printf("TelemetryAssertDiagTrack: %p\n", PVOID(tlg_TelemetryAssertDiagTrack - mz));
  if ( tlg_TelemetryAssertDiagTrack_KM != NULL )
    printf("TelemetryAssertDiagTrack_KM: %p\n", PVOID(tlg_TelemetryAssertDiagTrack_KM - mz));
}

#include <initguid.h>
DEFINE_GUID( TelemetryAssert_GUID, 0x6D1B249D, 0x131B, 0x468A, 0x89, 0x9B, 0xFB, 0x0A, 0xD9, 0x55, 0x17, 0x72);
DEFINE_GUID( TelemetryAssertDiagTrack_GUID, 0xAF2AE1C8, 0xCF6D, 0x4268, 0x81, 0x59, 0xFC, 0xCE, 0x3C, 0x2E, 0x67, 0xDB);
DEFINE_GUID( TelemetryAssertDiagTrack_KM_GUID, 0x07785021, 0xA524, 0x4DED, 0x81, 0x37, 0x8A, 0xB5, 0xC9, 0x39, 0x0F, 0xA8);

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

  exp = m_ed->find("NdisIMInitializeDeviceInstanceEx");
  if ( exp != NULL )
  {
    PBYTE res_addr = NULL;
    res += find_ndisFindMiniportOnGlobalList(mz + exp->rva, res_addr);
    if ( res_addr != NULL )
      res += hack_miniports(res_addr);
  }

  exp = m_ed->find("NdisOpenAdapterEx");
  if ( exp != NULL )
    res += hack_lock_list(mz + exp->rva, 300, m_ndisGlobalOpenListLock, m_ndisGlobalOpenList);

  // find tlg data
  res += find_tlg_by_guid((const PBYTE)&TelemetryAssert_GUID, mz, "NONPAGE", tlg_TelemetryAssert);
  res += find_tlg_by_guid((const PBYTE)&TelemetryAssertDiagTrack_GUID, mz, "NONPAGE", tlg_TelemetryAssertDiagTrack);
  res += find_tlg_by_guid((const PBYTE)&TelemetryAssertDiagTrack_KM_GUID, mz, "NONPAGE", tlg_TelemetryAssertDiagTrack_KM);
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

int ndis_hack::find_ndisFindMiniportOnGlobalList(PBYTE psp, PBYTE &out_res)
{
  regs_pad used_regs;
  if ( !setup(psp) )
    return 0;
  int state = 0; // 0 - wait for KeGetCurrentThread
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !is_inside_IAT(what) )
        used_regs.zero(get_reg(0));
    }
    if ( is_ldar(used_regs) )
      continue;
    if ( is_bl_reg() )
    {
      PBYTE what = (PBYTE)used_regs.get(get_reg(0));
      if ( is_iat_func(what, "KeGetCurrentThread") )
        state = 1;
    }
    if ( state && is_bl_jimm(out_res) )
      break;
  }
  return (out_res != NULL);
}

int ndis_hack::hack_miniports(PBYTE psp)
{
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while (edge_gen < 100)
  {
    for (auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter)
    {
      psp = *iter;
      if (m_verbose)
        printf("hack_miniports: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      edge_n++;
      int state = 0;
      regs_pad used_regs;
      DWORD base_reg = 0;
      for (DWORD i = 0; i < 100; i++)
      {
        if (!disasm(state) || is_ret())
          break;
        if ( check_jmps(cgraph) )
          continue;
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
          continue;
        }
        // call reg
        if ( is_bl_reg() )
        {
          if ( state )
            goto end;
          PBYTE what = (PBYTE)used_regs.get(get_reg(0));
          if ( is_iat_func(what, "KeAcquireSpinLockRaiseToDpc") )
          {
            state = 1;
            m_ndisMiniportListLock = (PBYTE)used_regs.get(AD_REG_X0);
          }
          continue;
        }
        if ( (1 == state) && is_ldr() ) 
        {
           PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
           if ( in_section(what, ".data") )
           {
             m_ndisMiniportList = what;
             base_reg = get_reg(0);
             state = 2;
           }
           continue;
        }
        if ( (1 == state) && is_ldr_rr() )
        {
           PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
           if ( in_section(what, ".data") )
           {
             m_ndisMiniportList = what;
             base_reg = get_reg(0);
             state = 2;
           }
           continue;
        }
        // to extract NextGlobalMiniport we need instruction like LDR base_reg, [base_reg + offset]
        if ( (2 == state) && is_ldr() && (base_reg == get_reg(0)) && (base_reg == get_reg(1)) )
        {
          m_NextGlobalMiniport = (DWORD)m_dis.operands[2].op_imm.bits;
          goto end;
        }
      }
      if ( state )
        goto end;
      cgraph.add_range(psp, m_psp - psp);
    }
    // prepare for next edge generation
    edge_gen++;
    if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
      break;    
  }
end:
  return (m_ndisMiniportListLock != NULL) && (m_ndisMiniportList != NULL);
}
