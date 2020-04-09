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
    void zero_data();
    int find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list, int verbose);
    // auxilary data
    PBYTE aux_KeAcquireSpinLockRaiseToDpc;
    // output data
    PBYTE m_ExNPagedLookasideLock;
    PBYTE m_ExNPagedLookasideListHead;
    PBYTE m_ExPagedLookasideLock;
    PBYTE m_ExPagedLookasideListHead;
};