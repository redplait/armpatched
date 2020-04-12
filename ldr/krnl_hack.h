#pragma once

#include "hack.h"

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
  protected:
    template <typename T>
    int check_jmps(T &graph)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      return 0;
    }
    template <typename T>
    int check_jmps(T &graph, int state)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      return 0;
    }
    void zero_data();
    int resolve_notify(PBYTE psp, PBYTE &lock, PBYTE &list);
    int find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list);
    int hack_tracepoints(PBYTE psp);
    int hack_ex_cbs_aux(PBYTE psp);
    int hack_x18(PBYTE psp, DWORD &off);
    int hack_x0_ldr(PBYTE psp, DWORD &off);
    // for ZwXXX functions - get index in sdt
    int hack_x16(PBYTE psp, DWORD &off);
    int get_nt_addr(const char *, PBYTE &);
    int hack_entry(PBYTE psp);
    int hack_sdt(PBYTE psp);
    int hack_ob_types(PBYTE psp);
    int hack_obref_type(PBYTE psp, PBYTE &off, const char *s_name);
    // auxilary data
    PBYTE aux_KeAcquireSpinLockRaiseToDpc;
    PBYTE aux_ExAcquirePushLockExclusiveEx;
    PBYTE aux_ObReferenceObjectByHandle;
    PBYTE aux_KfRaiseIrql;
    PBYTE aux_memset;
    // not exported
    PBYTE aux_ExAllocateCallBack;
    PBYTE aux_ExCompareExchangeCallBack;
    // lookaside lists data
    PBYTE m_ExNPagedLookasideLock;
    PBYTE m_ExNPagedLookasideListHead;
    PBYTE m_ExPagedLookasideLock;
    PBYTE m_ExPagedLookasideListHead;
    // tracepoints data
    PBYTE m_KiDynamicTraceEnabled;
    PBYTE m_KiTpStateLock;
    PBYTE m_KiTpHashTable;
    // KiServiceTable and friends from KiInitializeKernel
    PBYTE m_KeLoaderBlock;
    PBYTE m_KiServiceLimit;
    PBYTE m_KiServiceTable;
    // kernel notificators
    PBYTE m_PsWin32CallBack;
    PBYTE m_PspLoadImageNotifyRoutine;
    PBYTE m_PspLoadImageNotifyRoutineCount;
    // obtypes cookie & table
    PBYTE m_ObHeaderCookie;
    PBYTE m_ObTypeIndexTable;
    PBYTE m_ObpSymbolicLinkObjectType;
    PBYTE m_AlpcPortObjectType;
    // thread offsets
    DWORD m_stack_base_off;
    DWORD m_stack_limit_off;
    DWORD m_thread_id_off;
    DWORD m_thread_process_off;
    DWORD m_thread_prevmod_off;
    // process offsets
    DWORD m_proc_pid_off;
    DWORD m_proc_protection_off;
    DWORD m_proc_debport_off;
};