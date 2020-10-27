#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"

void ntoskrnl_hack::init_io()
{
  m_IopSessionNotificationLock = m_IopSessionNotificationQueueHead = NULL;
  m_IopUpdatePriorityCallback_size = 0;
  m_IopUpdatePriorityCallbackRoutine = m_IopUpdatePriorityCallbackRoutineCount = NULL;
  m_IopDatabaseResource = NULL;
  m_IopDiskFileSystemQueueHead = m_IopNetworkFileSystemQueueHead =
  m_IopCdRomFileSystemQueueHead = m_IopTapeFileSystemQueueHead = NULL;
}

void ntoskrnl_hack::dump_io(PBYTE mz) const
{
  if ( m_IopSessionNotificationLock != NULL )
    printf("IopSessionNotificationLock: %p\n", PVOID(m_IopSessionNotificationLock - mz));
  if ( m_IopSessionNotificationQueueHead != NULL )
    printf("IopSessionNotificationQueueHead: %p\n", PVOID(m_IopSessionNotificationQueueHead - mz));
  if ( m_IopUpdatePriorityCallbackRoutine != NULL )
    printf("IopUpdatePriorityCallbackRoutine: %p\n", PVOID(m_IopUpdatePriorityCallbackRoutine - mz));
  if ( m_IopUpdatePriorityCallbackRoutineCount != NULL )
    printf("IopUpdatePriorityCallbackRoutineCount: %p\n", PVOID(m_IopUpdatePriorityCallbackRoutineCount - mz));
  if ( m_IopUpdatePriorityCallback_size )
    printf("IopUpdatePriorityCallback size: %X\n", m_IopUpdatePriorityCallback_size);
  if ( m_IopDatabaseResource != NULL )
    printf("IopDatabaseResource: %p\n", PVOID(m_IopDatabaseResource - mz));
  if ( m_IopDiskFileSystemQueueHead != NULL )
    printf("IopDiskFileSystemQueueHead: %p\n", PVOID(m_IopDiskFileSystemQueueHead - mz));
  if ( m_IopNetworkFileSystemQueueHead != NULL )
    printf("IopNetworkFileSystemQueueHead: %p\n", PVOID(m_IopNetworkFileSystemQueueHead - mz));
  if ( m_IopCdRomFileSystemQueueHead != NULL )
    printf("IopCdRomFileSystemQueueHead: %p\n", PVOID(m_IopCdRomFileSystemQueueHead - mz));
  if ( m_IopTapeFileSystemQueueHead != NULL )
    printf("IopTapeFileSystemQueueHead: %p\n", PVOID(m_IopTapeFileSystemQueueHead - mz));
}

int ntoskrnl_hack::asgn_FileSystemQueueHead(DWORD state, PBYTE val)
{
  switch(state & 0xff)
  {
    case 8: m_IopDiskFileSystemQueueHead = val; return 1;
    case 3: m_IopCdRomFileSystemQueueHead = val; return 1;
    case 0x14: m_IopNetworkFileSystemQueueHead = val; return 1;
    case 0x20: m_IopTapeFileSystemQueueHead = val; return 1;
  }
  return 0;
}

int ntoskrnl_hack::disasm_IoRegisterFileSystem(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  int res = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("disasm_IoRegisterFileSystem: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( is_adrp(used_regs) )
          continue;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            continue;
          if ( state )
          {
            res += asgn_FileSystemQueueHead(state, what);
            break;
          }
        }
        // cmp reg, imm
        if ( (state & 0x100) && is_cmp_rimm() )
        {
          state = (BYTE)m_dis.operands[1].op_imm.bits | 0x100;
          continue;
        }
        // call
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
           if ( addr == aux_ExAcquireResourceExclusiveLite )
           {
             m_IopDatabaseResource = (PBYTE)used_regs.get(AD_REG_X0);
             state |= 0x100;
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
  return res;
}

int ntoskrnl_hack::disasm_IoRegisterPriorityCallback(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("disasm_IoRegisterPriorityCallback: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        // mov reg, imm
        if ( !state && is_mov_rimm() )
        {
          used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
          continue;
        }
        // call
        PBYTE addr = NULL;
        if ( is_bl_jimm(addr) )
        {
          if ( addr == aux_ExAllocatePoolWithTag || addr == aux_ExAllocatePool2 )
          {
            m_IopUpdatePriorityCallback_size = (DWORD)used_regs.get(AD_REG_X1);
            state = 1;
            continue;
          }
        }
        if ( state && is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            continue;
          if ( m_IopUpdatePriorityCallbackRoutine == NULL )
          {
            m_IopUpdatePriorityCallbackRoutine = what;
            continue;
          }
          if ( what != m_IopUpdatePriorityCallbackRoutine )
          {
            m_IopUpdatePriorityCallbackRoutineCount = what;
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
  return is_iopc_ok();
}

// state - 0 - wait for ExAcquirePushLockExclusiveEx
int ntoskrnl_hack::disasm_IoUnregisterContainerNotification(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_gen = 0;
  int edge_n = 0;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("disasm_IoUnregisterContainerNotification: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      int size = 0;
      for ( ; ; )
      {
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        if ( is_adrp(used_regs) )
          continue;
        if ( is_add() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".data") )
            continue;
          if ( state && what != m_IopSessionNotificationLock )
          {
            m_IopSessionNotificationQueueHead = what;
            goto end;
          }
        }
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
          if ( caddr == aux_ExAcquirePushLockExclusiveEx )
          {
            m_IopSessionNotificationLock = (PBYTE)used_regs.get(AD_REG_X0);
            state = 1;
            continue;
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
  return is_io_sess_cbs_ok();
}