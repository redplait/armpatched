#include "stdafx.h"
#include "bm_search.h"

static int suffix_match(const PBYTE needle, DWORD nlen, DWORD offset, DWORD suffixlen)
{
    if ( offset > suffixlen )
      return needle[offset - suffixlen - 1] != needle[nlen - suffixlen - 1] &&
        !memcmp(needle + nlen - suffixlen, needle + offset - suffixlen, suffixlen);
    else
      return !memcmp(needle + nlen - offset, needle, offset);
}

bm_search::bm_search()
  : m_pattern(NULL)
{
  m_skip = NULL;
  m_plen = 0;
}

bm_search::bm_search(const PBYTE pattern, DWORD plen)
 : m_pattern(pattern),
   m_plen(plen)
{
  make(pattern, plen);
}

int bm_search::make(const PBYTE pattern, DWORD plen)
{
  DWORD i;
  /* build stop-symbols table */
  for( i = 0; i < 0x100; ++i )
     occ[i] = -1;
  for( i = 0; i < plen - 1; ++i )
     occ[pattern[i]] = i;
  m_skip = (PDWORD)malloc(plen * sizeof(DWORD)); /* suffixes table */
  if ( m_skip == NULL )
    return 0;
  for( i = 0; i < plen; ++i )
  {
     DWORD offs = plen;
     while(offs && !suffix_match(pattern, plen, offs, i))
          --offs;
     m_skip[m_plen - i - 1] = plen - offs;
  }
  return 1;
}

int bm_search::set(const PBYTE pattern, DWORD plen)
{
  if ( m_skip != NULL )
  {
    free(m_skip);
    m_skip = NULL;
  }
  m_pattern = pattern;
  m_plen = plen;
  return make(pattern, plen);
}

bm_search::~bm_search()
{
  if ( m_skip != NULL )
  {
    free(m_skip);
    m_skip = NULL;
  }
}

const PBYTE bm_search::search(const PBYTE mem, size_t mlen)
{
  if ( (m_skip == NULL) || (m_pattern == NULL) )
    return NULL;
  DWORD i;
  for (size_t hpos = 0; hpos <= mlen - m_plen; )
  {
    i = m_plen - 1;
    while(m_pattern[i] == mem[i + hpos])
    {
       if (i == 0)
          return mem + hpos;
        --i;
    }
    /* no matching */
    hpos += max(LONG(m_skip[i]), LONG(i - occ[mem[i + hpos]]));
  }
  return NULL;
}
