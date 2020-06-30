#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

int ntoskrnl_hack::hack_obopen_type(PBYTE psp, PBYTE &off, const char *s_name)
{
  if ( !setup(psp) )
    return 0;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  off = NULL;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("hack_obopen_type: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( DWORD i = 0; i < 100; i++ )
      {
        if ( !disasm() || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr);
          break;
        }
        if ( is_adrp(used_regs) )
          continue;
        if ( is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, s_name) )
            used_regs.zero(get_reg(0));
        }
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
           if ( caddr == aux_ObOpenObjectByPointer )
           {
             off = (PBYTE)used_regs.get(AD_REG_X4);
             goto end;
           }
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
  return (off != NULL);
}

int ntoskrnl_hack::hack_obref_type(PBYTE psp, PBYTE &off, const char *s_name)
{
  if ( !setup(psp) )
    return 0;
  cf_graph<PBYTE> cgraph;
  std::list<PBYTE> addr_list;
  addr_list.push_back(psp);
  int edge_n = 0;
  int edge_gen = 0;
  off = NULL;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = *iter;
      if ( m_verbose )
        printf("hack_obref_type: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( DWORD i = 0; i < 100; i++ )
      {
        if ( !disasm() || is_ret() )
          break;
        if ( check_jmps(cgraph) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr);
          break;
        }
        if ( is_adrp(used_regs) )
          continue;
        if ( is_ldr() ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, s_name) )
            used_regs.zero(get_reg(0));
        }
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
           if ( caddr == aux_ObReferenceObjectByHandle )
           {
             off = (PBYTE)used_regs.get(AD_REG_X2);
             goto end;
           }
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
  return (off != NULL);
}

int ntoskrnl_hack::hack_ObFindHandleForObject(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  int state = 0; // 0 - wait for first call
                 // 1 - wait for ExEnumHandleTable
                 // 2 - add x0, imm
  regs_pad used_regs;
  PBYTE first_call = NULL;
  PBYTE enum_proc = NULL;
  for ( DWORD i = 0; i < 30; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( (1 == state) && in_section(what, "PAGE") ) // ObpEnumFindHandleProcedure located in PAGE section
         enum_proc = what;
       else if ( (2 == state) && get_reg(0) == AD_REG_X0 )
       {
         eproc_ProcessLock_off = (DWORD)m_dis.operands[2].op_imm.bits;
         break;
       }
       continue;
    }
    // bl
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( !state )
      {
        first_call = caddr;
        state = 1;
        continue;
      }
      if ( caddr == aux_ExEnumHandleTable )
        state = 2;
    }
  }
  int res = 0;
  if ( enum_proc != NULL )
    res += hack_enum_tab(enum_proc);
  if ( first_call != NULL )
    res += hack_ObReferenceProcessHandleTable(first_call);
  return res + (eproc_ObjectTable_off != 0 ? 1 : 0);
}

int ntoskrnl_hack::hack_ObReferenceProcessHandleTable(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  int state = 0; // 0 - wait for first call
  DWORD arg_reg = 0;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    // register to store arg0
    if ( !state && is_mov_rr() && get_reg(1) == AD_REG_X0 )
      arg_reg = get_reg(0);
    // bl
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( state )
        break;
      state++;
    }
    // ldr
    if ( state && is_ldr() && get_reg(1) == arg_reg )
    {
      eproc_ObjectTable_off = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
  }
  return (eproc_ObjectTable_off != 0);
}

int ntoskrnl_hack::hack_enum_tab(PBYTE psp)
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
        printf("hack_enum_tab: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
      if (cgraph.in_ranges(psp))
        continue;
      if (!setup(psp))
        continue;
      DWORD x0_add = 0;
      edge_n++;
      for (DWORD i = 0; i < 100; i++)
      {
        if (!disasm() || is_ret())
          break;
        if (check_jmps(cgraph))
          continue;
        // add 
        if (is_add() && get_reg(0) == AD_REG_X0)
          x0_add = (DWORD)m_dis.operands[2].op_imm.bits;
        // bl
        PBYTE caddr = NULL;
        if (is_bl_jimm(caddr))
        {
          if (caddr == aux_ExfUnblockPushLock)
          {
            ObjectTable_pushlock_off = x0_add;
            goto end;
          }
        }
      }
      cgraph.add_range(psp, m_psp - psp);
    }
    // prepare for next edge generation
    edge_gen++;
    if (!cgraph.delete_ranges(&cgraph.ranges, &addr_list))
      break;
  }
end:
  return (ObjectTable_pushlock_off != 0);
}


int ntoskrnl_hack::hack_ob_types(PBYTE psp)
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
    // ldrb for cookie
    if ( !state && is_ldrb() ) 
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, "ALMOSTRO") )
         used_regs.zero(get_reg(0));
       else {
         m_ObHeaderCookie = what;
         state = 1;
       }
    }
    // add for index tab
    if ( state && is_add() )
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( !in_section(what, "ALMOSTRO") )
         used_regs.zero(get_reg(0));
       else {
         m_ObTypeIndexTable = what;
         break;
       }
    }
  }
  return (m_ObHeaderCookie != NULL) && (m_ObTypeIndexTable != NULL);
}
