#include "stdafx.h"
#include "krnl_hack.h"
#include "cf_graph.h"
#include "bm_search.h"

void ntoskrnl_hack::zero_data()
{
  // fill auxilary data
  init_aux("KeAcquireSpinLockAtDpcLevel", aux_KeAcquireSpinLockAtDpcLevel);
  init_aux("ExAcquireSpinLockExclusiveAtDpcLevel", aux_ExAcquireSpinLockExclusiveAtDpcLevel);
  init_aux("KeAcquireSpinLockRaiseToDpc", aux_KeAcquireSpinLockRaiseToDpc);
  init_aux("ExAcquirePushLockExclusiveEx", aux_ExAcquirePushLockExclusiveEx);
  init_aux("ObReferenceObjectByPointer", aux_ObReferenceObjectByPointer);
  init_aux("ObReferenceObjectByHandle", aux_ObReferenceObjectByHandle);
  init_aux("ObOpenObjectByPointer", aux_ObOpenObjectByPointer);
  init_aux("ObCreateObjectTypeEx", aux_ObCreateObjectTypeEx);
  init_aux("EtwRegister", aux_EtwRegister);
  init_aux("ExAcquireFastMutexUnsafe", aux_ExAcquireFastMutexUnsafe);
  init_aux("ExAcquireFastMutex", aux_ExAcquireFastMutex);
  init_aux("KeAcquireGuardedMutex", aux_KeAcquireGuardedMutex);
  init_aux("KfRaiseIrql", aux_KfRaiseIrql);
  init_aux("memset", aux_memset);
  init_aux("MmUserProbeAddress", aux_MmUserProbeAddress);
  init_aux("MmSystemRangeStart", aux_MmSystemRangeStart);
  init_aux("MmHighestUserAddress", aux_MmHighestUserAddress);
  init_aux("MmBadPointer", aux_MmBadPointer);
  init_aux("ExAllocatePoolWithTag", aux_ExAllocatePoolWithTag);
  init_aux("ExEnumHandleTable", aux_ExEnumHandleTable);
  init_aux("ExfUnblockPushLock", aux_ExfUnblockPushLock);
  init_aux("RtlImageNtHeader", aux_RtlImageNtHeader);
  init_aux("PsInitialSystemProcess", aux_PsInitialSystemProcess);
  aux_PsGetCurrentServerSiloGlobals = aux_ExAllocateCallBack = aux_ExCompareExchangeCallBack = aux_KxAcquireSpinLock =
  aux_dispatch_icall = aux_tp_stab = NULL;
  // zero output data
  m_HvlpAa64Connected = m_HvlpFlags = NULL;
  m_CrashdmpCallTable = NULL;
  init_etw();
  init_silo();
  init_emp();
  init_wmi();
  init_bugcheck_data();
  m_MiGetPteAddress = m_pte_base_addr = NULL;
  eproc_ObjectTable_off = ObjectTable_pushlock_off = eproc_ProcessLock_off = 0;
  m_CmRegistryTransactionType = m_ExpKeyedEventObjectType = m_ExpWorkerFactoryObjectType = m_IopWaitCompletionPacketObjectType = m_ObpDirectoryObjectType = NULL;
  m_ExNPagedLookasideLock = NULL;
  m_ExNPagedLookasideListHead = NULL;
  m_ExPagedLookasideLock = NULL;
  m_ExPagedLookasideListHead = NULL;
  m_KiSystemServiceTraceCallbackTable_size = 0;
  init_tracepoints();
  m_stack_base_off = m_stack_limit_off = m_thread_id_off = m_thread_process_off = m_thread_prevmod_off = m_thread_silo_off = m_thread_TopLevelIrp_off = 0;
  m_proc_pid_off = m_proc_peb_off = m_proc_job_off = m_proc_protection_off = m_proc_debport_off = m_proc_flags3_off = m_proc_secport_off = m_proc_wow64_off = m_proc_win32proc_off = m_proc_DxgProcess_off = 0;
  m_KeLoaderBlock = m_KiServiceLimit = m_KiServiceTable = m_SeCiCallbacks = NULL;
  m_SeCiCallbacks_size = 0;
  m_ObHeaderCookie = m_ObTypeIndexTable = m_ObpSymbolicLinkObjectType = m_AlpcPortObjectType = m_DbgkDebugObjectType = m_ExProfileObjectType = NULL;
  init_dbg_data();
  m_PsWin32CallBack = NULL;
  m_PspLoadImageNotifyRoutine = m_PspLoadImageNotifyRoutineCount = NULL;
  m_CmpCallbackListLock = m_CallbackListHead = NULL;
  m_PspCreateThreadNotifyRoutine = m_PspCreateThreadNotifyRoutineCount = NULL;
  m_SepRmNotifyMutex = m_SeFileSystemNotifyRoutinesExHead = NULL;
  m_ExpHostListLock = m_ExpHostList = NULL;
  m_KiWaitNever = m_KiWaitAlways = NULL;
  m_pnp_item_size = 0;
  m_PnpDeviceClassNotifyLock = m_PnpDeviceClassNotifyList = NULL;
  zero_sign_data();
}

void ntoskrnl_hack::dump() const
{
  PBYTE mz = m_pe->base_addr();
  if ( aux_dispatch_icall != NULL )
    printf("guard_dispatch_icall: %p\n", PVOID(aux_dispatch_icall - mz));
  if ( m_CrashdmpCallTable != NULL ) 
    printf("CrashdmpCallTable: %p\n", PVOID(m_CrashdmpCallTable - mz));
  // lookaside lists & locks
  if ( m_ExNPagedLookasideLock != NULL )
    printf("ExNPagedLookasideLock: %p\n", PVOID(m_ExNPagedLookasideLock - mz));
  if ( m_ExNPagedLookasideListHead != NULL )
    printf("ExNPagedLookasideListHead: %p\n", PVOID(m_ExNPagedLookasideListHead - mz));
  if ( m_ExPagedLookasideLock != NULL )
    printf("ExPagedLookasideLock: %p\n", PVOID(m_ExPagedLookasideLock - mz));
  if ( m_ExPagedLookasideListHead != NULL )
    printf("ExPagedLookasideListHead: %p\n", PVOID(m_ExPagedLookasideListHead - mz));
  // etw
  dump_etw(mz);
  // dump pnp data
  dump_pnp(mz);
  // dump tracepoints
  dump_tracepoints(mz);
  // bugcheck data
  dump_bugcheck_data(mz);

  if ( m_KeLoaderBlock != NULL )
    printf("KeLoaderBlock: %p\n", PVOID(m_KeLoaderBlock - mz));
  if ( m_KiServiceLimit != NULL )
    printf("KiServiceLimit: %p\n", PVOID(m_KiServiceLimit - mz));
  if ( m_KiServiceTable != NULL )
    printf("KiServiceTable: %p\n", PVOID(m_KiServiceTable - mz));
  if ( m_SeCiCallbacks != NULL )
    printf("SeCiCallbacks: %p size %X\n", PVOID(m_SeCiCallbacks - mz), m_SeCiCallbacks_size);
  if ( m_ObHeaderCookie != NULL )
    printf("ObHeaderCookie: %p\n", PVOID(m_ObHeaderCookie - mz));
  if ( m_ObTypeIndexTable != NULL )
    printf("ObTypeIndexTable: %p\n", PVOID(m_ObTypeIndexTable - mz));
  if ( m_ObpSymbolicLinkObjectType != NULL ) 
    printf("ObpSymbolicLinkObjectType: %p\n", PVOID(m_ObpSymbolicLinkObjectType - mz));
  if ( m_CmRegistryTransactionType != NULL )
    printf("CmRegistryTransactionType: %p\n", PVOID(m_CmRegistryTransactionType - mz));
  if ( m_ExpKeyedEventObjectType != NULL )
    printf("ExpKeyedEventObjectType: %p\n", PVOID(m_ExpKeyedEventObjectType - mz));
  if ( m_ExpWorkerFactoryObjectType != NULL )
    printf("ExpWorkerFactoryObjectType: %p\n", PVOID(m_ExpWorkerFactoryObjectType - mz));
  if ( m_IopWaitCompletionPacketObjectType != NULL )
    printf("IopWaitCompletionPacketObjectType: %p\n", PVOID(m_IopWaitCompletionPacketObjectType - mz));
  if ( m_ObpDirectoryObjectType != NULL )
    printf("ObpDirectoryObjectType: %p\n", PVOID(m_ObpDirectoryObjectType - mz));
  if ( m_ExProfileObjectType != NULL )
    printf("ExProfileObjectType: %p\n", PVOID(m_ExProfileObjectType - mz));
  if ( m_EtwpRegistrationObjectType != NULL )
    printf("EtwpRegistrationObjectType: %p\n", PVOID(m_EtwpRegistrationObjectType - mz));
  if ( m_AlpcPortObjectType != NULL )
    printf("AlpcPortObjectType: %p\n", PVOID(m_AlpcPortObjectType - mz));
  // dbg data
  dump_dbg_data(mz);

  if ( m_PsWin32CallBack != NULL )
    printf("PsWin32CallBack: %p\n", PVOID(m_PsWin32CallBack - mz));
  if ( m_ExpHostListLock != NULL )
    printf("ExpHostListLock: %p\n", PVOID(m_ExpHostListLock - mz));
  if ( m_ExpHostList != NULL )
    printf("ExpHostList: %p\n", PVOID(m_ExpHostList - mz));
  if ( m_CmpCallbackListLock != NULL )
    printf("CmpCallbackListLock: %p\n", PVOID(m_CmpCallbackListLock - mz));
  if ( m_CallbackListHead != NULL )
    printf("CallbackListHead: %p\n", PVOID(m_CallbackListHead - mz));
  if ( m_PspLoadImageNotifyRoutine != NULL )
    printf("PspLoadImageNotifyRoutine: %p\n", PVOID(m_PspLoadImageNotifyRoutine - mz));
  if ( m_PspLoadImageNotifyRoutineCount != NULL )
    printf("PspLoadImageNotifyRoutineCount: %p\n", PVOID(m_PspLoadImageNotifyRoutineCount - mz));
  if ( m_PspCreateThreadNotifyRoutine != NULL )
    printf("PspCreateThreadNotifyRoutine: %p\n", PVOID(m_PspCreateThreadNotifyRoutine - mz));
  if ( m_PspCreateThreadNotifyRoutineCount != NULL )
    printf("PspCreateThreadNotifyRoutineCount: %p\n", PVOID(m_PspCreateThreadNotifyRoutineCount - mz));
  if ( m_SepRmNotifyMutex != NULL )
    printf("SepRmNotifyMutex: %p\n", PVOID(m_SepRmNotifyMutex - mz));
  if ( m_SeFileSystemNotifyRoutinesExHead != NULL )
    printf("SeFileSystemNotifyRoutinesExHead: %p\n", PVOID(m_SeFileSystemNotifyRoutinesExHead - mz));
  if ( m_KiWaitNever != NULL )
    printf("KiWaitNever: %p\n", PVOID(m_KiWaitNever - mz));
  if ( m_KiWaitAlways != NULL )
    printf("KiWaitAlways: %p\n", PVOID(m_KiWaitAlways - mz));
  // thread offsets
  if ( m_stack_base_off )
    printf("KTHREAD.StackBase offset:  %X\n", m_stack_base_off);
  if ( m_stack_limit_off )
    printf("KTHREAD.StackLimit offset: %X\n", m_stack_limit_off);
  if ( m_thread_id_off )
    printf("ETHREAD.ThreadId offset:   %X\n", m_thread_id_off);
  if ( m_thread_process_off )
    printf("KTHREAD.Process offset:    %X\n", m_thread_process_off);
  if ( m_thread_prevmod_off )
    printf("KTHREAD.PreviousMode offset: %X\n", m_thread_prevmod_off);
  if ( m_thread_silo_off )
    printf("ETHREAD.Silo offset: %X\n", m_thread_silo_off);
  if ( m_thread_TopLevelIrp_off )
    printf("ETHREAD.TopLevelIrp offset: %X\n", m_thread_TopLevelIrp_off);
  // process offsets
  if ( m_proc_pid_off )
    printf("EPROCESS.UniqueProcessId offset: %X\n", m_proc_pid_off);
  if ( m_proc_peb_off )
    printf("EPROCESS.Peb offset: %X\n", m_proc_peb_off);
  if ( m_proc_job_off )
    printf("EPROCESS.Job offset: %X\n", m_proc_job_off);
  if ( m_proc_protection_off )
    printf("EPROCESS.Protection offset: %X\n", m_proc_protection_off);
  if ( m_proc_debport_off )
    printf("EPROCESS.DebugPort: %X\n", m_proc_debport_off);
  if ( m_proc_secport_off )
    printf("EPROCESS.SecurityPort: %X\n", m_proc_secport_off);
  if ( m_proc_wow64_off )
    printf("EPROCESS.WoW64Process: %X\n", m_proc_wow64_off);
  if ( m_proc_win32proc_off )
    printf("EPROCESS.Win32Process: %X\n", m_proc_win32proc_off);
  if ( m_proc_DxgProcess_off )
    printf("EPROCESS.DxgProcess offset: %X\n", m_proc_DxgProcess_off);
  if ( m_proc_flags3_off )
    printf("EPROCESS.Flags3 offset: %X\n", m_proc_flags3_off);
  if ( eproc_ObjectTable_off )
    printf("EPROCESS.ObjectTable: %X\n", eproc_ObjectTable_off);
  if ( eproc_ProcessLock_off )
    printf("EPROCESS.RundownProtect: %X\n", eproc_ProcessLock_off);
  if ( ObjectTable_pushlock_off )
    printf("HANDLE_TABLE.HandleContentionEvent: %X\n", ObjectTable_pushlock_off);
  // wmi
  dump_wmi(mz);
  // silo
  dump_silo(mz);
  // emp
  dump_emp(mz);
  // kpte
  if ( m_MiGetPteAddress != NULL )
    printf("MiGetPteAddress: %p\n", PVOID(m_MiGetPteAddress - mz));
  if ( m_pte_base_addr != NULL )
    printf("pte_base_addr at: %p\n", PVOID(m_pte_base_addr - mz));
  // hypervisor
  if ( m_HvlpFlags != NULL )
    printf("HvlpFlags: %p\n", PVOID(m_HvlpFlags - mz));
  if ( m_HvlpAa64Connected != NULL )
    printf("HvlpAa64Connected: %p\n", PVOID(m_HvlpAa64Connected - mz));
  dump_sign_data();
}

int ntoskrnl_hack::hack(int verbose)
{
  m_verbose = verbose;
  if ( m_ed == NULL )
    return 0;
  int res = 0;
  PBYTE mz = m_pe->base_addr();
  // first resolve guard_dispatch_icall
  const export_item *exp = m_ed->find("RtlGetCompressionWorkSpaceSize");
  if ( exp != NULL )
    res += find_first_jmp(mz + exp->rva, aux_dispatch_icall);
  if ( aux_dispatch_icall != NULL )
    res += find_crash_tab(mz);
  // lookaside lists & locks
  exp = m_ed->find("ExInitializePagedLookasideList");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += find_lock_list(next, m_ExPagedLookasideLock, m_ExPagedLookasideListHead);
  }
  exp = m_ed->find("ExInitializeNPagedLookasideList");
  if ( exp != NULL ) 
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += find_lock_list(next, m_ExNPagedLookasideLock, m_ExNPagedLookasideListHead);
  }
  exp = m_ed->find("MmFreeNonCachedMemory");
  if ( exp != NULL )
  {
    res += find_first_bl(mz + exp->rva, m_MiGetPteAddress);
    if ( m_MiGetPteAddress != NULL )
     res += disasm_MiGetPteAddress(m_MiGetPteAddress);
  }
  // WMI data
  res += hack_wmi(mz);

  exp = m_ed->find("IoRegisterPlugPlayNotification");
  if ( exp != NULL )
    res += disasm_IoRegisterPlugPlayNotification(mz + exp->rva);

  // tracepoints
  exp = m_ed->find("KeSetTracepoint");
  if ( exp != NULL ) 
   try
   {
     res += hack_tracepoints(mz + exp->rva);
   } catch(std::bad_alloc)
   { }
  if ( m_KiTpHashTable != NULL )
    res += find_trace_sdt(mz);

  if ( !m_stab.empty() )
    res += find_stab_types(mz);

  // ssdt
  DWORD ep = m_pe->entry_point();
  if ( ep )
  try
  {
    res += hack_entry(mz + ep);
  } catch(std::bad_alloc)
  { }

  if ( m_KiServiceTable != NULL )
  {
    PBYTE addr = NULL;
    if ( get_nt_addr("ZwQuerySymbolicLinkObject", addr) )
      res += hack_obref_type(addr, m_ObpSymbolicLinkObjectType, ".data");
//    if ( get_nt_addr("ZwWaitForDebugEvent", addr) )
//      res += hack_obref_type(addr, m_DbgkDebugObjectType, "ALMOSTRO");
    addr = NULL;
    if ( get_nt_addr("ZwDeleteKey", addr) )
     res += hack_CmpTraceRoutine(addr);
  }
  if ( m_DbgkDebugObjectType == NULL )
    res += find_DbgkDebugObjectType_by_sign(mz, 0xC0000712);
  res += find_DbgpInsertDebugPrintCallback_by_sign(mz);
  exp = m_ed->find("DbgQueryDebugFilterState");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += hack_kd_masks(next);
  }
  exp = m_ed->find("KdRefreshDebuggerNotPresent");
  if ( exp != NULL )
    res += resolve_KdPitchDebugger(mz + exp->rva);

  if ( m_KeLoaderBlock != NULL )
  {
    res += find_SepInitializeCodeIntegrity_by_sign(mz, 0xA00000A);
    if ( m_SeCiCallbacks == NULL )
    res += find_SepInitializeCodeIntegrity_by_sign(mz, 0xA000009);
    if ( m_SeCiCallbacks == NULL )
      res += find_SepInitializeCodeIntegrity_by_sign(mz, 0xA000008);
    if ( m_SeCiCallbacks == NULL )
      res += find_SepInitializeCodeIntegrity_by_sign(mz, 0xA000007);
  }

  // bugcheck data
  exp = m_ed->find("FsRtlUninitializeFileLock");
  if ( exp != NULL )
    res += find_KxAcquireSpinLock(mz + exp->rva);
  exp = m_ed->find("KeRegisterBugCheckCallback");
  if ( exp != NULL )
    res += hack_bugcheck(mz + exp->rva);
  exp = m_ed->find("KeRegisterBugCheckReasonCallback");
  if ( exp != NULL )
    res += hack_bugcheck_reason(mz + exp->rva);

  // silo data
  exp = m_ed->find("PsStartSiloMonitor");
  if ( exp != NULL )
    res += hack_start_silo(mz + exp->rva);
  exp = m_ed->find("PsGetServerSiloServiceSessionId");
  if ( exp != NULL )
    res += hack_silo_global(mz + exp->rva);

  exp = m_ed->find("ExRegisterExtension");
  if ( exp != NULL )
    res += hack_reg_ext(mz + exp->rva);
  exp = m_ed->find("KeSetTimerEx");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_bl(mz + exp->rva, next) )
      res += hack_timers(next);
    else
      res += hack_timers(mz + exp->rva);
  }
  // emp data
  exp = m_ed->find("EmpProviderRegister");
  if ( exp != NULL )
    res += hack_emp(mz + exp->rva);
  // etw data
  res += find_EtwpSessionDemuxObjectType(mz);
  res += hack_etw_handles(mz);
  res += hack_tlg_handles(mz);
  // kernel notifications
  exp = m_ed->find("PsEstablishWin32Callouts");
  if ( exp != NULL )
    res += hack_ex_cbs_aux(mz + exp->rva);
  exp = m_ed->find("PsSetLoadImageNotifyRoutineEx");
  if ( exp != NULL )
    res += resolve_notify(mz + exp->rva, m_PspLoadImageNotifyRoutine, m_PspLoadImageNotifyRoutineCount);
  exp = m_ed->find("PsSetCreateThreadNotifyRoutine");
  if ( exp != NULL )
  {
    PBYTE next = NULL;
    if ( find_first_jmp(mz + exp->rva, next) )
      res += resolve_notify(next, m_PspCreateThreadNotifyRoutine, m_PspCreateThreadNotifyRoutineCount);
  }
  exp = m_ed->find("SeRegisterLogonSessionTerminatedRoutineEx");
  if ( exp != NULL )
    res += hask_se_logon(mz + exp->rva);
  exp = m_ed->find("CmUnRegisterCallback");
  if ( exp != NULL )
  {
    res += hack_cm_cbs(mz + exp->rva);
    if ( !is_cm_cbs_ok() )
      res += hack_cm_cbs2(mz + exp->rva);
  }
  // obtypes
  exp = m_ed->find("ObReferenceObjectByPointerWithTag");
  if ( exp != NULL ) 
    res += hack_ob_types(mz + exp->rva);
  exp = m_ed->find("ObFindHandleForObject");
  if ( exp != NULL ) 
    res += hack_ObFindHandleForObject(mz + exp->rva);
  exp = m_ed->find("NtRequestWaitReplyPort");
  if ( exp != NULL )
    res += hack_obref_type(mz + exp->rva, m_AlpcPortObjectType, "ALMOSTRO");
  // thread offsets
  exp = m_ed->find("PsGetCurrentThreadId");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_id_off);
  exp = m_ed->find("PsGetCurrentThreadStackLimit");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_stack_limit_off);
  exp = m_ed->find("PsGetCurrentThreadStackBase");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_stack_base_off);
  exp = m_ed->find("PsGetCurrentThreadProcess");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_process_off);
  exp = m_ed->find("ExGetPreviousMode");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_prevmod_off);
  exp = m_ed->find("PsIsCurrentThreadInServerSilo");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_silo_off);
  exp = m_ed->find("IoGetTopLevelIrp");
  if ( exp != NULL )
    res += hack_x18(mz + exp->rva, m_thread_TopLevelIrp_off);
  // process offsets
  exp = m_ed->find("PsGetProcessId");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_pid_off);
  exp = m_ed->find("PsGetProcessPeb");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_peb_off);
  exp = m_ed->find("PsGetProcessJob");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_job_off);
  exp = m_ed->find("PsGetProcessWow64Process");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_wow64_off);
  exp = m_ed->find("PsGetProcessWin32Process");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_win32proc_off);
  exp = m_ed->find("PsGetProcessDxgProcess");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_DxgProcess_off);
  exp = m_ed->find("PsGetProcessProtection");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_protection_off);
  exp = m_ed->find("PsGetProcessDebugPort");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_debport_off);
  exp = m_ed->find("PsGetProcessSecurityPort");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_secport_off);
  exp = m_ed->find("PsIsSystemProcess");
  if ( exp != NULL )
    res += hack_x0_ldr(mz + exp->rva, m_proc_flags3_off);

  // hypervisor
  exp = m_ed->find("HvlQueryActiveProcessors");
  if ( exp != NULL )
    res += hack_hvl_flags(mz + exp->rva, m_HvlpFlags, "ALMOSTRO");
  exp = m_ed->find("HvlQueryConnection");
  if ( exp != NULL )
    res += hack_hvl_flags(mz + exp->rva, m_HvlpAa64Connected, "CFGRO");

  res += try_find_PsKernelRangeList(mz);
  return res;
}

int ntoskrnl_hack::hack_hvl_flags(PBYTE psp, PBYTE &out_res, const char *s_name)
{
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( in_section(what, s_name) )
        out_res = what;
      break;
    }
    if ( is_ldr() ) 
    {
       PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
       if ( in_section(what, s_name) )
         out_res = what;
       break;
    }
  }
  return (out_res != NULL);
}

int ntoskrnl_hack::find_DbgkDebugObjectType_by_sign(PBYTE mz, DWORD sign)
{
  // try search in PAGE section
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
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
#ifdef _DEBUG
    printf("find_DbgkDebugObjectType_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( NULL == func )
      continue;
    if ( hack_obref_type(func, m_DbgkDebugObjectType, "ALMOSTRO") )
      return 1;
  }
  return 0;
}

int ntoskrnl_hack::find_SepInitializeCodeIntegrity_by_sign(PBYTE mz, DWORD sign)
{
  // try search in PAGE section
  const one_section *s = m_pe->find_section_by_name("PAGE");
  if ( NULL == s )
    return 0;
  PBYTE start = mz + s->va;
  PBYTE end = start + s->size;
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
#ifdef _DEBUG
    printf("find_SepInitializeCodeIntegrity_by_sign: found at %p, func %p\n", *citer - mz, func);
#endif/* _DEBUG */
    if ( NULL == func )
      continue;
    if ( disasm_SepInitializeCodeIntegrity(func, *citer) )
      return 1;
  }
  return 0;
}

int ntoskrnl_hack::disasm_SepInitializeCodeIntegrity(PBYTE psp, PBYTE found)
{
  if ( !setup(psp) )
    return 0;
  PBYTE last_data = NULL;
  DWORD data_size = 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 50; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( is_mov_rimm() )
    {
      data_size = (DWORD)m_dis.operands[1].op_imm.bits;
    }
    if ( (last_data == NULL) && is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( in_section(what, ".data") )
        last_data = what;
      continue;
    }
    if ( is_ldr_off() )
    {
      if ( (PBYTE)m_dis.operands[1].op_imm.bits == found )
      {
        m_SeCiCallbacks = last_data;
        m_SeCiCallbacks_size = data_size;
        break;
      }
    }
  }
  return (m_SeCiCallbacks != NULL);

}

int ntoskrnl_hack::get_nt_addr(const char *name, PBYTE &addr)
{
  if ( m_KiServiceTable == NULL )
    return 0;
  const export_item *exp = m_ed->find(name);
  if ( NULL == exp )
    return 0;
  DWORD idx = 0;
  PBYTE mz = m_pe->base_addr();
  if ( !hack_x16(mz + exp->rva, idx) )
    return 0;
  addr = mz + *((PDWORD)m_KiServiceTable + idx);
  return 1;
}

int ntoskrnl_hack::hack_x16(PBYTE psp, DWORD &off)
{
  if ( !setup(psp) )
    return 0;
  off = 0;
  for ( DWORD i = 0; i < 4; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_mov_rimm() && get_reg(0) == AD_REG_X16 )
    {
      off = (DWORD)m_dis.operands[1].op_imm.bits;
      break;
    }
  }
  return (off != 0);
}

// x0 holds first arg - in functions like PsGetProcessXXX
int ntoskrnl_hack::hack_x0_ldr(PBYTE psp, DWORD &off)
{
  if ( !setup(psp) )
    return 0;
  off = 0;
  for ( DWORD i = 0; i < 5; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_ldrxx(AD_INSTR_LDRB, AD_INSTR_LDR) && get_reg(1) == AD_REG_X0 )
    {
      off = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
  }
  return (off != 0);
}

// according to https://docs.microsoft.com/ru-ru/cpp/build/arm64-windows-abi-conventions?view=vs-2019
// x18 reg points to KPCR in kernel mode (and in user mode, points to TEB)
int ntoskrnl_hack::hack_x18(PBYTE psp, DWORD &off)
{
  if ( !setup(psp) )
    return 0;
  int reg = -1;
  off = 0;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_ldr() && get_reg(1) == AD_REG_X18 )
      reg = get_reg(0);
    if ( is_ldrxx(AD_INSTR_LDR, AD_INSTR_LDRSB, AD_INSTR_ADD) && reg == get_reg(1) )
    {
      off = (DWORD)m_dis.operands[2].op_imm.bits;
      break;
    }
  }
  return (off != 0);
}

int ntoskrnl_hack::hack_timers(PBYTE psp)
{
  int state = 0; // 0 - expect loading of KiWaitNever
                 // 1 - expect loading of KiWaitAlways
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 40; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( !state && is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "ALMOSTRO") )
        used_regs.zero(get_reg(0));
      else
      {
        m_KiWaitNever = what;
        state = 1;
        continue;
      }
    }
    if ( state && is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "ALMOSTRO") )
        used_regs.zero(get_reg(0));
      else {
        m_KiWaitAlways = what;
        break;
      }
    }
  }
  return (m_KiWaitNever != NULL) && (m_KiWaitAlways != NULL);
}

int ntoskrnl_hack::hask_se_logon(PBYTE psp)
{
  int state = 0; // 0 - expect ExAcquireFastMutexUnsafe, arg in x0 is mutex
                 // 1 - wait for loading address from PAGEDATA
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( !state && is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
       continue;
    }
    if ( state && is_ldr() ) 
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "PAGEDATA") )
        used_regs.zero(get_reg(0));
      else {
        m_SeFileSystemNotifyRoutinesExHead = what;
        break;
      }
    }
    // check for call
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( caddr == aux_ExAcquireFastMutexUnsafe )
      {
        m_SepRmNotifyMutex = (PBYTE)used_regs.get(AD_REG_X0);
        state = 1;
        continue;
      }
    }
  }
  return (m_SepRmNotifyMutex != NULL) && (m_SeFileSystemNotifyRoutinesExHead != NULL);
}

int ntoskrnl_hack::hack_reg_ext(PBYTE psp)
{
  int state = 0; // 0 - expect some unexported lock, arg in x0 is lock
                 // 1 - wait for ExpFindHost - located in PAGE section
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( !state && is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, "PAGEDATA") )
        used_regs.zero(get_reg(0));
    }
    // check for call
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( !state )
      {
        m_ExpHostListLock = (PBYTE)used_regs.get(AD_REG_X0);
        state = 1;
        continue;
      } else {
        if ( !in_section(caddr, "PAGE") )
          continue;
        find_first_load(caddr, "PAGEDATA", m_ExpHostList);
        break;
      }
    }
  }
  return (m_ExpHostListLock != NULL);
}

int ntoskrnl_hack::hack_ex_cbs_aux(PBYTE psp)
{
  int state = 0; // 0 - expect for first call ExAllocateCallBack
                 // 1 - loading some address inside .data section
                 // 2 - expect for ExCompareExchangeCallBack call
  if ( !setup(psp) )
    return 0;
  regs_pad used_regs;
  for ( DWORD i = 0; i < 100; i++ )
  {
    if ( !disasm(state) || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
    if ( (1 == state) && is_add() )
    {
      PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
      if ( !in_section(what, ".data") )
        used_regs.zero(get_reg(0));
      else {
        m_PsWin32CallBack = what;
        state = 2;
      }
    }
    // check for call
    PBYTE caddr = NULL;
    if ( is_bl_jimm(caddr) )
    {
      if ( !state )
      {
         aux_ExAllocateCallBack = caddr;
         state = 1;
      } else if ( state == 2 )
      {
         aux_ExCompareExchangeCallBack = caddr;
         break;
      }
    }
  }
  return (m_PsWin32CallBack != NULL);
}

int ntoskrnl_hack::find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list)
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
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_adrp(used_regs) )
      continue;
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

int ntoskrnl_hack::hack_sdt(PBYTE psp)
{
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
        printf("hack_sdt: %p, edge_gen %d, edge_n %d\n", psp, edge_gen, edge_n);
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
        if ( is_ldrxx(AD_INSTR_ADD, AD_INSTR_LDR) ) 
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( !in_section(what, ".rdata") )
            used_regs.zero(get_reg(0));
        }
        // check for call
        PBYTE caddr = NULL;
        if ( is_bl_jimm(caddr) )
        {
          if ( used_regs.get(AD_REG_X2) != NULL &&
               used_regs.get(AD_REG_X0) != NULL
             )
          {
            m_KiServiceLimit = (PBYTE)used_regs.get(AD_REG_X2);
            m_KiServiceTable = (PBYTE)used_regs.get(AD_REG_X0);
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
  return (m_KiServiceLimit != NULL) && (m_KiServiceTable);
}

int ntoskrnl_hack::hack_entry(PBYTE psp)
{
  statefull_graph<PBYTE, int> cgraph;
  std::list<std::pair<PBYTE, int> > addr_list;
  auto curr = std::make_pair(psp, 0);
  addr_list.push_back(curr);
  int edge_n = 0;
  int edge_gen = 0;
  PBYTE KiInitializeKernel = NULL;
  while( edge_gen < 100 )
  {
    for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
    {
      psp = iter->first;
      int state = iter->second;
      if ( m_verbose )
        printf("hack_entry: %p, state %d, edge_gen %d, edge_n %d\n", psp, state, edge_gen, edge_n);
      if ( cgraph.in_ranges(psp) )
        continue;
      if ( !setup(psp) )
        continue;
      regs_pad used_regs;
      edge_n++;
      for ( ; ; )
      {
        // state 0 - at start function
        //       1 - after memset, can grab KeLoaderBlock
        //       2 - after call reg, next call will be KiInitializeKernel
        if ( !disasm(state) || is_ret() )
          break;
        if ( check_jmps(cgraph, state) )
          continue;
        // check for last b xxx
        PBYTE b_addr = NULL;
        if ( is_b_jimm(b_addr) )
        {
          cgraph.add(b_addr, state);
          break;
        }
        // check for call
        if ( is_bl_jimm(b_addr) )
        {
          if ( b_addr == aux_memset )
            state = 1;
          else if ( b_addr == aux_KfRaiseIrql )
            state = 2;
          else if ( 2 == state )
          {
            KiInitializeKernel = b_addr;
            goto end;
          }
        }
        if ( is_bl_reg() )
          state = 2;
        if ( (m_KeLoaderBlock == NULL) && (1 == state) && is_adrp(used_regs) )
          continue;
        if ( (m_KeLoaderBlock == NULL) && (1 == state) && is_str() )
        {
          PBYTE what = (PBYTE)used_regs.add(get_reg(0), get_reg(1), m_dis.operands[2].op_imm.bits);
          if ( in_section(what, "ALMOSTRO") )          
            m_KeLoaderBlock = what;
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
  if ( KiInitializeKernel == NULL )
    return 0;
  return hack_sdt(KiInitializeKernel);
}

int ntoskrnl_hack::disasm_MiGetPteAddress(PBYTE psp)
{
  if ( !setup(psp) )
    return 0;
  for ( DWORD i = 0; i < 5; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_ldr_off() )
    {
      m_pte_base_addr = (PBYTE)m_dis.operands[1].op_imm.bits;
      break;
    }
  }
  return (m_pte_base_addr != NULL);
}
