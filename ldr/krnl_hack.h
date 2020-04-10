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
    int find_lock_list(PBYTE psp, PBYTE &lock, PBYTE &list, int verbose);
    int hack_tracepoints(PBYTE psp, int verbose);
    // auxilary data
    PBYTE aux_KeAcquireSpinLockRaiseToDpc;
    PBYTE aux_ExAcquirePushLockExclusiveEx;
    // output data
    PBYTE m_ExNPagedLookasideLock;
    PBYTE m_ExNPagedLookasideListHead;
    PBYTE m_ExPagedLookasideLock;
    PBYTE m_ExPagedLookasideListHead;
    // tracepoints data
    PBYTE m_KiDynamicTraceEnabled;
    PBYTE m_KiTpStateLock;
    PBYTE m_KiTpHashTable;
};