#pragma once

#include "hack.h"

DWORD tp_hash(const char *name);

struct etw_descriptor
{
  BYTE guid[16];
  const char *name;
  PBYTE aux_addr;
  PBYTE etw_addr;
};

struct tlg_descriptor
{
  BYTE guid[16];
  const char *name;
  PBYTE etw_addr;
  const char *section_name;
};

class ntoskrnl_hack: public arm64_hack
{
  public:
    ntoskrnl_hack(arm64_pe_file *pe, exports_dict *ed)
     : arm64_hack(pe, ed)
    {
      zero_data();
    }
    virtual ~ntoskrnl_hack()
    { }
    int hack(int verbose);
    void dump() const;
    // validators
    inline int is_cm_cbs_ok() const
    {
      return (m_CmpCallbackListLock != NULL) && (m_CallbackListHead != NULL);
    }
    inline int is_kse_ok() const
    {
      return (m_KseEngine != NULL) && (m_kse_lock != NULL);
    }
    inline int is_iopc_ok() const
    {
      return (m_IopUpdatePriorityCallbackRoutine != NULL) && (m_IopUpdatePriorityCallbackRoutineCount != NULL);
    }
    inline int is_wmi_ctx_ok() const
    {
      return (m_wmi_logger_ctx_size != 0) && (m_wmi_logger_ctx_loggername_offset != 0);
    }
    inline int is_po_cbs_ok() const
    {
      return (m_PopSettingLock != NULL) && (m_PopRegisteredPowerSettingCallbacks != NULL);
    }
    inline int is_io_sess_cbs_ok() const
    {
      return (m_IopSessionNotificationLock != NULL) && (m_IopSessionNotificationQueueHead != NULL);
    }
  protected:
    // init methods
    void init_wmi();
    void init_wnf();
    void init_io();
    void init_kse();
    void init_emp();
    void init_etw();
    void init_silo();
    void init_po();
    void init_tracepoints();
    void init_dbg_data();
    void init_bugcheck_data();
    // dumpers
    void dump_io(PBYTE mz) const;
    void dump_po(PBYTE mz) const;
    void dump_wnf(PBYTE mz) const;
    void dump_wmi(PBYTE mz) const;
    void dump_etw(PBYTE mz) const;
    void dump_emp(PBYTE mz) const;
    void dump_kse(PBYTE mz) const;
    void dump_silo(PBYTE mz) const;
    void dump_pnp(PBYTE mz) const;
    void dump_dbg_data(PBYTE mz) const;
    void dump_tracepoints(PBYTE mz) const;
    void dump_bugcheck_data(PBYTE mz) const;

    void zero_data();
    void zero_sign_data();
    void dump_sign_data() const;
    int hack_wmi(PBYTE mz);
    int try_find_PsKernelRangeList(PBYTE mz);
    int disasm_MiGetPteAddress(PBYTE psp);
    int resolve_notify(PBYTE psp, PBYTE &lock, PBYTE &list);
    int find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list);
    int hack_tracepoints(PBYTE psp);
    int find_trace_sdt(PBYTE mz);
    int find_stab_types(PBYTE mz);
    int hack_emp(PBYTE mz);
    int find_emp_list(PBYTE mz);
    int hack_ex_cbs_aux(PBYTE psp);
    int find_KxAcquireSpinLock(PBYTE psp);
    int hack_bugcheck(PBYTE psp);
    int hack_bugcheck_reason(PBYTE psp);
    int hack_timers(PBYTE psp);
    int hack_x18(PBYTE psp, DWORD &off);
    int hack_x0_ldr(PBYTE psp, DWORD &off);
    int hack_hvl_flags(PBYTE psp, PBYTE &out_res, const char *s_name);
    // for ZwXXX functions - get index in sdt
    int hack_x16(PBYTE psp, DWORD &off);
    int get_nt_addr(const char *, PBYTE &);
    int hack_entry(PBYTE psp);
    int hack_sdt(PBYTE psp);
    int hack_ob_types(PBYTE psp);
    int hack_obref_type(PBYTE psp, PBYTE &off, const char *s_name);
    int hack_obopen_type(PBYTE psp, PBYTE &off, const char *s_name);
    int hack_obpref_type(PBYTE psp, PBYTE &off, const char *s_name, PBYTE ignore_type);
    int hack_reg_ext(PBYTE psp);
    int hask_se_logon(PBYTE psp);
    int hack_cm_cbs(PBYTE psp);
    int hack_cm_cbs2(PBYTE psp); // under 19041 lock inside separate function CmpLockCallbackListExclusive
    int hack_cm_lock(PBYTE psp);
    int hack_etw_handles(PBYTE mz);
    int hack_tlg_handles(PBYTE mz);
    int hack_mcgen_contexts(PBYTE mz);
    int disasm_KseUnregisterShim(PBYTE);
    int disasm_EtwpInitialize(PBYTE);
    void find_guid_addr(PBYTE mz, etw_descriptor *);
    int hack_EtwpSessionDemuxObjectType(PBYTE);
    int find_EtwpSessionDemuxObjectType(PBYTE mz);
    int hack_EtwpAllocGuidEntry(PBYTE);
    int find_EtwpAllocGuidEntry_by_sign(PBYTE mz);
    int find_EtwpInitLoggerContext_by_sign(PBYTE mz);
    int hack_EtwpInitLoggerContext(PBYTE, PBYTE mz);
    int find_DbgkDebugObjectType_by_sign(PBYTE mz, DWORD sign, int use_open);
    int find_SepInitializeCodeIntegrity_by_sign(PBYTE mz, DWORD sign);
    int disasm_SepInitializeCodeIntegrity(PBYTE, PBYTE where);
    int disasm_IoRegisterPlugPlayNotification(PBYTE);
    int hack_ObFindHandleForObject(PBYTE);
    int hack_enum_tab(PBYTE);
    int hack_ObReferenceProcessHandleTable(PBYTE);
    int try_wmip_obj(PBYTE);
    int hack_wmi_clock(PBYTE);
    int disasm_IoWMIQueryAllData(PBYTE);
    int disasm_IoWMIDeviceObjectToProviderId(PBYTE, PBYTE &);
    int disasm_WmipDoFindRegEntryByDevice(PBYTE);
    int hack_start_silo(PBYTE);
    int hack_start_silo_2004(PBYTE);
    int try_hach_silo_lock(PBYTE);
    int hack_silo_global(PBYTE);
    int find_crash_tab(PBYTE mz);
    int disasm_crash_tab(PBYTE);
    int try_KiGetSystemServiceTraceTable_by_sign(PBYTE mz);
    int hack_KiSystemServiceTraceCallbackTable(PBYTE mz, PBYTE psp);
    int find_DbgpInsertDebugPrintCallback_by_sign(PBYTE mz);
    int hack_DbgpInsertDebugPrintCallback(PBYTE);
    int resolve_KdPitchDebugger(PBYTE);
    int hack_kd_masks(PBYTE);
    int hack_CmpTraceRoutine(PBYTE);
    int try_wnf_proc_ctx(PBYTE, PBYTE mz);
    int disasm_ExpWnfCreateProcessContext(PBYTE, PBYTE mz);
    int disasm_PsGetCurrentServerSiloGlobals(PBYTE);
    int find_ejob_siloglobals(PBYTE);
    int disasm_EtwpTraceMessageVa(PBYTE);
    int disasm_EtwpTraceMessageVa2(PBYTE);
    int find_DisplayStringFilter(PBYTE);
    int disasm_IoRegisterPriorityCallback(PBYTE);
    int disasm_PoRegisterPowerSettingCallback(PBYTE);
    int disasm_IoUnregisterContainerNotification(PBYTE);
    int disasm_IoRegisterFileSystem(PBYTE);
    int asgn_FileSystemQueueHead(DWORD state, PBYTE);
    int disasm_IoRegisterFsRegistrationChangeMountAware(PBYTE);
    // auxilary data
    PBYTE aux_MmUserProbeAddress;
    PBYTE aux_MmSystemRangeStart;
    PBYTE aux_MmHighestUserAddress;
    PBYTE aux_MmBadPointer;
    PBYTE aux_ExAcquireResourceExclusiveLite;
    PBYTE aux_KeAcquireSpinLockAtDpcLevel;
    PBYTE aux_ExAcquireSpinLockExclusiveAtDpcLevel;
    PBYTE aux_KeAcquireSpinLockRaiseToDpc;
    PBYTE aux_ExAcquirePushLockExclusiveEx;
    PBYTE aux_ObReferenceObjectByHandle;
    PBYTE aux_ObpReferenceObjectByHandleWithTag; // non-expored. can be found from ObReferenceObjectByHandle
    PBYTE aux_ObReferenceObjectByPointer;
    PBYTE aux_ObOpenObjectByPointer;
    PBYTE aux_ExAcquireFastMutexUnsafe;
    PBYTE aux_ExAcquireFastMutex;
    PBYTE aux_KeAcquireGuardedMutex;
    PBYTE aux_ExAllocatePoolWithTag;
    PBYTE aux_ExAllocatePool2;
    PBYTE aux_ExFreePoolWithTag;
    PBYTE aux_KfRaiseIrql;
    PBYTE aux_RtlInitUnicodeString;
    PBYTE aux_KeUnstackDetachProcess;
    PBYTE aux_memset;
    PBYTE aux_memcmp;
    PBYTE aux_ExEnumHandleTable;
    PBYTE aux_ExfUnblockPushLock;
    PBYTE aux_RtlImageNtHeader;
    PBYTE aux_PsInitialSystemProcess;
    PBYTE aux_ObCreateObjectTypeEx;
    PBYTE aux_EtwRegister;
    // not exported
    PBYTE aux_ExAllocateCallBack;
    PBYTE aux_ExCompareExchangeCallBack;
    PBYTE aux_dispatch_icall; // guard_dispatch_icall
    PBYTE aux_PsGetCurrentServerSiloGlobals;
    PBYTE aux_KxAcquireSpinLock; // from FsRtlUninitializeFileLock
    // lookaside lists data
    PBYTE m_ExNPagedLookasideLock;
    PBYTE m_ExNPagedLookasideListHead;
    PBYTE m_ExPagedLookasideLock;
    PBYTE m_ExPagedLookasideListHead;
    // undocumented invb trash
    PBYTE m_InbvDisplayFilter;
    // kernel shims
    PBYTE m_KseEngine;
    PBYTE m_kse_lock;
    // io data
    PBYTE m_IopSessionNotificationLock;
    PBYTE m_IopSessionNotificationQueueHead;
    PBYTE m_IopFsNotifyChangeQueueHead;
    // IoRegisterFileSystem
    PBYTE m_IopDatabaseResource;
    PBYTE m_IopDiskFileSystemQueueHead;  // 8
    PBYTE m_IopNetworkFileSystemQueueHead; // 0x14
    PBYTE m_IopCdRomFileSystemQueueHead; // 3
    PBYTE m_IopTapeFileSystemQueueHead;  // 0x20
    // PoRegisterPowerSettingCallback data
    DWORD m_PoRegisterPowerSettingCallback_size;
    PBYTE m_PopSettingLock;
    PBYTE m_PopRegisteredPowerSettingCallbacks;
    // data from IoRegisterPriorityCallback
    DWORD m_IopUpdatePriorityCallback_size;
    PBYTE m_IopUpdatePriorityCallbackRoutine;
    PBYTE m_IopUpdatePriorityCallbackRoutineCount;
    // bugcheck data
    PBYTE m_KeBugCheckCallbackLock;
    PBYTE m_KeBugCheckCallbackListHead;
    PBYTE m_KeBugCheckReasonCallbackListHead;
    PBYTE m_KeBugCheckAddRemovePagesCallbackListHead;
    // tracepoints data
    PBYTE m_KiDynamicTraceEnabled;
    PBYTE m_KiTpStateLock;
    PBYTE m_KiTpHashTable;
    PBYTE m_KiSystemServiceTraceCallbackTable;
    DWORD m_KiSystemServiceTraceCallbackTable_size;
    PBYTE aux_tp_stab;
    std::map<DWORD, PBYTE> m_stab;
    // KiServiceTable and friends from KiInitializeKernel
    PBYTE m_KeLoaderBlock;
    PBYTE m_KiServiceLimit;
    PBYTE m_KiServiceTable;
    // from SepInitializeCodeIntegrity
    PBYTE m_SeCiCallbacks;
    DWORD m_SeCiCallbacks_size;
    // PlugPlayNotifications
    DWORD m_pnp_item_size;
    PBYTE m_PnpDeviceClassNotifyLock;
    PBYTE m_PnpDeviceClassNotifyList;
    // extensions
    PBYTE m_ExpHostListLock;
    PBYTE m_ExpHostList; // from ExpFindHost
    // CrashdmpCallTable
    PBYTE m_CrashdmpCallTable;
    // kernel notificators
    PBYTE m_PsWin32CallBack;
    PBYTE m_SepRmNotifyMutex;
    PBYTE m_SeFileSystemNotifyRoutinesExHead;
    PBYTE m_PspLoadImageNotifyRoutine;
    PBYTE m_PspLoadImageNotifyRoutineCount;
    PBYTE m_PspCreateThreadNotifyRoutine;
    PBYTE m_PspCreateThreadNotifyRoutineCount;
    PBYTE m_CmpCallbackListLock;
    PBYTE m_CallbackListHead;
    // obtypes cookie & table
    PBYTE m_ObHeaderCookie;
    PBYTE m_ObTypeIndexTable;
    // some non-exported object types
    PBYTE m_CmRegistryTransactionType;
    PBYTE m_ExpKeyedEventObjectType;
    PBYTE m_ExpWorkerFactoryObjectType;
    PBYTE m_IopWaitCompletionPacketObjectType;
    PBYTE m_ObpDirectoryObjectType;
    PBYTE m_ExProfileObjectType;
    PBYTE m_EtwpRegistrationObjectType;
    // object tables data
    DWORD eproc_ObjectTable_off;
    DWORD ObjectTable_pushlock_off;
    DWORD eproc_ProcessLock_off;
    // etw stuff
    PBYTE m_CmpTraceRoutine;
    PBYTE m_EtwpSessionDemuxObjectType;
    std::vector<etw_descriptor> m_etw_handles;
    void asgn_etw_handle(PBYTE guid_addr, PBYTE value);
    // tlg stuff
    std::vector<tlg_descriptor> m_tlg_handles;
    // mcgeb stuff
    PBYTE MS_KernelCc_Provider_Context;
    PBYTE MS_StorageTiering_Provider_Context;
    PBYTE IoMgrProvider_Context;
    PBYTE MS_KernelPnP_Provider_Context;
    // kpte stuff
    PBYTE m_MiGetPteAddress;
    PBYTE m_pte_base_addr;
    // symlinks data
    PBYTE m_ObpSymbolicLinkObjectType;
    PBYTE m_AlpcPortObjectType;
    // timers
    PBYTE m_KiWaitNever;
    PBYTE m_KiWaitAlways;
    // thread offsets
    DWORD m_stack_base_off;
    DWORD m_stack_limit_off;
    DWORD m_thread_id_off;
    DWORD m_thread_process_off;
    DWORD m_thread_prevmod_off;
    DWORD m_thread_silo_off;
    DWORD m_thread_TopLevelIrp_off;
    // process offsets
    DWORD m_proc_pid_off;
    DWORD m_proc_peb_off;
    DWORD m_proc_job_off;
    DWORD m_proc_protection_off;
    DWORD m_proc_debport_off;
    DWORD m_proc_secport_off;
    DWORD m_proc_wow64_off;
    DWORD m_proc_win32proc_off;
    DWORD m_proc_DxgProcess_off;
    DWORD m_proc_flags3_off;
    // DbgkDebugObjectType - from NtCreateDebugObject
    PBYTE m_DbgkDebugObjectType;
    // DebugPrintCallback data
    PBYTE m_RtlpDebugPrintCallbackLock;
    PBYTE m_RtlpDebugPrintCallbackList;
    DWORD m_DebugPrintCallback_size;
    PBYTE m_KdComponentTable;
    DWORD m_KdComponentTable_size;
    PBYTE m_Kd_WIN2000_Mask;
    PBYTE m_KdPitchDebugger;
    // wmi data
    PBYTE m_WmipGuidObjectType;
    PBYTE m_WmipRegistrationSpinLock;
    PBYTE m_WmipInUseRegEntryHead;
    DWORD m_EtwSiloState_offset;      // ESERVERSILO_GLOBALS.EtwSiloState offset
    DWORD m_etw_guid_entry_size;
    DWORD m_wmi_logger_ctx_size;
    DWORD m_wmi_logger_ctx_loggername_offset;
    DWORD m_wmi_logger_ctx_starttime_offset;
    DWORD m_ejob_silo_globals_offset; // EJOB.ServerSiloGlobals offset
    PBYTE m_EtwpHostSiloState;
    // silo data
    PBYTE m_PspSiloMonitorLock;
    PBYTE m_PspSiloMonitorList;
    PBYTE m_PspHostSiloGlobals;
    // wnf data
    PBYTE m_ExpWnfProcessesListLock;
    PBYTE m_ExpWnfProcessesListHead;
    DWORD m_wnf_proc_ctx_size; // sizeof(WNF_PROCESS_CONTEXT) - from ExpWnfCreateProcessContext
    // emp data
    PBYTE m_EmpDatabaseLock;
    PBYTE m_EmpEntryListHead;
    DWORD m_emp_item_size;
    // hypervisor data
    PBYTE m_HvlpAa64Connected;
    PBYTE m_HvlpFlags;
    // data from PsKernelRangeList
    PBYTE m_PspPicoProviderRoutines;
    DWORD m_PspPicoProviderRoutines_size;
    PBYTE m_HvcallCodeVa;
    DWORD m_HvcallCodeVa_size;
    PBYTE m_PsWin32NullCallBack;
    DWORD m_PsWin32NullCallBack_size;
    PBYTE m_PspSystemMitigationOptions;
    DWORD m_PspSystemMitigationOptions_size;
    PBYTE m_KdpBootedNodebug;
    PBYTE m_KiDynamicTraceCallouts;
    DWORD m_KiDynamicTraceCallouts_size;
    // since 19603?
    PBYTE m_BBTBuffer;
    DWORD m_BBTBuffer_size;
    PBYTE m_KeArm64VectorBase;
    DWORD m_KeArm64VectorBase_size;
    PBYTE m_PsAltSystemCallHandlers;
    DWORD m_PsAltSystemCallHandlers_size;
    // new state change object types
    PBYTE m_PspProcessStateChangeType;
    PBYTE m_PspThreadStateChangeType;
};