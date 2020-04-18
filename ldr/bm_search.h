#pragma once

class bm_search
{
  public:
    bm_search(const PBYTE pattern, DWORD plen);
    bm_search();
   ~bm_search();
    int set(const PBYTE pattern, DWORD plen);
    const PBYTE search(const PBYTE mem, size_t mlen);
  protected:
    int make(const PBYTE pattern, DWORD plen);
    LONG occ[0x100];
    PBYTE m_pattern;
    DWORD m_plen;
    PDWORD m_skip;
};
