#pragma once

#include "hack.h"

class ntdll_hack: public arm64_hack
{
  public:
    ntdll_hack(arm64_pe_file *pe, exports_dict *ed)
     : arm64_hack(pe, ed)
    {
      zero_data();
    }
    virtual ~ntdll_hack()
    { }
    int hack(int verbose);
    void dump() const;
  protected:
    void zero_data();
    int hack_veh(PBYTE);
    int hack_add_dll_dirs(PBYTE);
    int hack_dll_dir(PBYTE);
    int find_dll_ntfy(PBYTE);
    int find_shut(PBYTE);
    int find_wnf_root(PBYTE);
    int hack_wnf_root(PBYTE);
    int hack_func_tab(PBYTE);
    int hack_func_tree(PBYTE);
    int find_ptr_map(PBYTE);
    int find_props(PBYTE);
    int disasm_LdrQueryImageFileExecutionOptions(PBYTE);
    // aux data
    PBYTE aux_RtlAcquireSRWLockExclusive;
    PBYTE aux_RtlAllocateHeap;
    PBYTE aux_RtlEnterCriticalSection;
    PBYTE aux_RtlRunOnceExecuteOnce;
    PBYTE aux_LdrpMrdataLock; // not exported
    PBYTE aux_bsearch;
    // output data
    PBYTE m_LdrpVectorHandlerList;
    PBYTE m_LdrpDllDirectoryLock;
    PBYTE m_LdrpUserDllDirectories;
    PBYTE m_LdrpPolicyBits;
    PBYTE m_LdrpDllDirectory;
    PBYTE m_LdrpDllNotificationLock;
    PBYTE m_LdrpDllNotificationList;
    PBYTE m_LdrpShutdownInProgress;
    PBYTE wnf_block;
    DWORD wnf_block_size;
    PBYTE m_RtlpDynamicFunctionTableLock;
    PBYTE m_RtlpDynamicFunctionTable;
    PBYTE m_RtlpDynamicFunctionTableTree;
    DWORD m_func_tab_tree_item_size;
    // from RtlCompareExchangePointerMapping
    PBYTE m_RtlpPtrTreeLock;
    PBYTE m_RtlpPtrTree;
    // from RtlCompareExchangePropertyStore
    PBYTE m_RtlpPropStoreLock;
    PBYTE m_RtlpPropStoreEntriesActiveCount;
    PBYTE m_RtlpPropStoreEntries;
    // from LdrQueryImageFileExecutionOptions
    PBYTE m_LdrpIsSecureProcess;
};