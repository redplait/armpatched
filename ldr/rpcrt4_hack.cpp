#include "stdafx.h"
#include "rpcrt4_hack.h"
#include "bm_search.h"
#include "cf_graph.h"

void rpcrt4_hack::zero_data()
{
  // zero output data
  m_RpcHasBeenInitialized = m_GlobalRpcServer = NULL;
  m_ForwardFunction_offset = 0;
  m_MgmtAuthorizationFn = NULL;
  m_RpcEtwGuid_Context = m_RpcLegacyEvents_Context = m_Networking_CorrelationHandle = NULL;
  m_WmiTraceData = NULL;
}

void rpcrt4_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( m_RpcHasBeenInitialized != NULL )
    printf("RpcHasBeenInitialized: %p\n", PVOID(m_RpcHasBeenInitialized - mz));
  if ( m_GlobalRpcServer != NULL )
    printf("GlobalRpcServer: %p\n", PVOID(m_GlobalRpcServer - mz));
  if ( m_ForwardFunction_offset )
    printf("RPC_SERVER.ForwardFunction offset: %X\n", m_ForwardFunction_offset);
  if ( m_MgmtAuthorizationFn != NULL )
    printf("MgmtAuthorizationFn: %p\n", PVOID(m_MgmtAuthorizationFn - mz));
  if ( m_WmiTraceData != NULL )
    printf("WmiTraceData: %p\n", PVOID(m_WmiTraceData - mz));
  // etw data
  if ( m_RpcEtwGuid_Context != NULL )
    printf("RpcEtwGuid_Context: %p\n", PVOID(m_RpcEtwGuid_Context - mz));
  if ( m_RpcLegacyEvents_Context != NULL )
    printf("RpcLegacyEvents_Context: %p\n", PVOID(m_RpcLegacyEvents_Context - mz));
  if ( m_Networking_CorrelationHandle != NULL )
    printf("Networking_CorrelationHandle: %p\n", PVOID(m_Networking_CorrelationHandle - mz));
}

int rpcrt4_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  const export_item *exp = m_ed->find("RpcMgmtSetAuthorizationFn");
  if ( exp != NULL )
    res += hack_auth_fn(mz + exp->rva);
  // see http://redplait.blogspot.com/2017/11/how-to-find-rpcrt4globalrpcserver.html
  exp = m_ed->find("I_RpcServerRegisterForwardFunction");
  if ( exp != NULL )
    res += find_rpc_server(mz + exp->rva);
  exp = m_ed->find("I_RpcEnableWmiTrace");
  if ( exp != NULL )
    res += find_wmi_data(mz + exp->rva);
  // try to find etw data
  res += find_etw_by_signs(mz);
  return res;
}

int rpcrt4_hack::find_etw_by_signs(PBYTE mz)
{
  const BYTE rpc_guid[16] = { 0x32, 0x2B, 0xD5, 0x6A, 9, 0xD6, 0xE9, 0x4B, 0xAE, 7, 0xCE, 0x8D, 0xAE, 0x93, 0x7E, 0x39 };
  const BYTE net_guid[16] = { 0xF0, 0x54, 0xED, 0x83, 0x48, 0x4D, 0x45, 0x4E, 0xB1, 0x6E, 0x72, 0x6F, 0xFD, 0x1F, 0xA4, 0xAF };
  const BYTE legacy_guid[16] = { 0xC7, 0xD7, 0xAE, 0xF4, 0x98, 0xA8, 0x27, 0x46, 0xB0, 0x53, 0x44, 0xA7, 0xCA, 0xA1, 0x2F, 0xCD }; 
  aux_RpcEtwGuid = aux_Networking_CorrelationId = aux_RpcLegacyEvents = NULL;
  int res = find_etw_guid((const PBYTE)rpc_guid, mz, aux_RpcEtwGuid);
  res += find_etw_guid((const PBYTE)net_guid, mz, aux_Networking_CorrelationId);
  res += find_etw_guid((const PBYTE)legacy_guid, mz, aux_RpcLegacyEvents);
  if ( aux_RpcEtwGuid != NULL )
    res += resolve_etw(aux_RpcEtwGuid, mz, m_RpcEtwGuid_Context);
  if ( aux_Networking_CorrelationId != NULL )
    res += resolve_etw(aux_Networking_CorrelationId, mz, m_Networking_CorrelationHandle);
  if ( aux_RpcLegacyEvents != NULL )
    res += resolve_etw(aux_RpcLegacyEvents, mz, m_RpcLegacyEvents_Context);
  return res;
}

int rpcrt4_hack::resolve_etw(PBYTE what, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".text");
  if ( NULL == s )
    return 0;
  xref_finder xf;
  PBYTE res = xf.find(mz + s->va, s->size, what);
  if ( res == NULL )
    return 0;
  PBYTE func = find_pdata(res);
  if ( NULL == func )
    return 0;
  return disasm_etw(func, what, out_res);
}

int rpcrt4_hack::disasm_etw(PBYTE psp, PBYTE aux_addr, PBYTE &out_res)
{
  if ( !setup(psp) )
    return 0;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("hack_etw: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      int state = 0;
      for ( DWORD i = 0; i < 1000; i++ )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( what == aux_addr )
            state = 1;
          continue;
        }
        // check for bl
        PBYTE caddr = NULL;
        if ( state && is_bl_jimm(caddr) )
        {
          out_res = (PBYTE)used_regs.get(AD_REG_X3);
          goto end;
        }
        // check for blr
        if ( state && is_bl_reg() )
        {
          out_res = (PBYTE)used_regs.get(AD_REG_X3);
          goto end;
        }
      }
      cgraph.add_range(psp, m_psp - psp);
    }
    // prepare for next edge generation
    edge_gen++;
    if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
      break;    
  }
end:
  return (out_res != NULL);
}

int rpcrt4_hack::find_etw_guid(const PBYTE sign, PBYTE mz, PBYTE &out_res)
{
  const one_section *s = m_pe->find_section_by_name(".rdata");
  if ( NULL == s )
    return 0;
  PBYTE curr = mz + s->va;
  PBYTE end = curr + s->size;
  bm_search srch(sign, 16);
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
    curr = fres + 16;
  }
  if ( founds.empty() )
    return 0;
  if ( 1 != founds.size() )
    return 0;
  out_res = *(founds.cbegin());
  return 1;
}

// RpcMgmtSetAuthorizationFn
int rpcrt4_hack::hack_auth_fn(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 12; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_str() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( in_section(what, ".data") )
         m_MgmtAuthorizationFn = what;
       break;
    }
  }
  return (m_MgmtAuthorizationFn != NULL);
}

// I_RpcEnableWmiTrace
int rpcrt4_hack::find_wmi_data(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 12; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( in_section(what, ".data") )
         m_WmiTraceData = what;
       break;
    }
  }
  return (m_WmiTraceData != NULL);
}

int rpcrt4_hack::find_rpc_server(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  int state = 0; // 0 - wait for pcHasBeenInitialized
                 // 1 - GlobalRpcServer
  int base_reg = -1;
  for ( DWORD i = 0; i < 20; i++ )
  {
    if ( !disasm(state) || is_ret() )
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
       if ( !state )
       {
         m_RpcHasBeenInitialized = what;
         state = 1;
         continue;
       } else if ( 1 == state )
       {
         m_GlobalRpcServer = what;
         base_reg = get_reg(0);
         state = 2;
         continue;
       }
       break;
    }
    // find offset to function - something like str reg, [base_reg + imm]
    if ( (2 == state) && is_str() )
    {
      if ( base_reg == get_reg(1) )
      {
        m_ForwardFunction_offset = (DWORD)m_dis.operands[2].op_imm.bits;
        break;
      }
    }
  }
  return (m_GlobalRpcServer != NULL);
}