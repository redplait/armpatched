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
    // aux data
    PBYTE aux_RtlAcquireSRWLockExclusive;
    PBYTE aux_RtlAllocateHeap;
    PBYTE aux_LdrpMrdataLock; // not exported
    // output data
    PBYTE m_LdrpVectorHandlerList;
    PBYTE m_LdrpDllDirectoryLock;
    PBYTE m_LdrpUserDllDirectories;
    PBYTE m_LdrpPolicyBits;
    PBYTE m_LdrpDllDirectory;
};