#include "stdafx.h"
#include "krnl_hack.h"
#include "bm_search.h"

void ntoskrnl_hack::zero_sign_data()
{
  m_PspPicoProviderRoutines =
  m_HvcallCodeVa = m_PsWin32NullCallBack =
  m_PspSystemMitigationOptions =
  m_KdpBootedNodebug =
  m_KiDynamicTraceCallouts = 
  m_BBTBuffer = m_KeArm64VectorBase =
  m_PsAltSystemCallHandlers = NULL;
  // sizes
  m_PspPicoProviderRoutines_size =
  m_HvcallCodeVa_size =
  m_PsWin32NullCallBack_size =
  m_PspSystemMitigationOptions_size =
  m_KiDynamicTraceCallouts_size =
  m_BBTBuffer_size =
  m_KeArm64VectorBase_size =
  m_PsAltSystemCallHandlers_size = 0;
}

void ntoskrnl_hack::dump_sign_data() const
{
    PBYTE mz = m_pe->base_addr();
  if ( m_PspPicoProviderRoutines != NULL )
    printf("PspPicoProviderRoutines: %p, size %X\n", PVOID(m_PspPicoProviderRoutines - mz), m_PspPicoProviderRoutines_size);
  if ( m_HvcallCodeVa != NULL )
    printf("HvcallCodeVa: %p, size %X\n", PVOID(m_HvcallCodeVa - mz), m_HvcallCodeVa_size);
  if ( m_PsWin32NullCallBack != NULL )
    printf("PsWin32NullCallBack: %p, size %X\n", PVOID(m_PsWin32NullCallBack - mz), m_PsWin32NullCallBack_size);
  if ( m_PspSystemMitigationOptions != NULL )
    printf("PspSystemMitigationOptions: %p, size %X\n", PVOID(m_PspSystemMitigationOptions - mz), m_PspSystemMitigationOptions_size);
  if ( m_KdpBootedNodebug != NULL )
    printf("KdpBootedNodebug: %p\n", PVOID(m_KdpBootedNodebug - mz));
  if ( m_KiDynamicTraceCallouts != NULL )
    printf("KiDynamicTraceCallouts: %p, size %X\n", PVOID(m_KiDynamicTraceCallouts - mz), m_KiDynamicTraceCallouts_size);
  if ( m_BBTBuffer != NULL )
    printf("BBTBuffer: %p, size %X\n", PVOID(m_BBTBuffer - mz), m_BBTBuffer_size);
  if ( m_KeArm64VectorBase != NULL )
    printf("KeArm64VectorBase: %p, size %X\n", PVOID(m_KeArm64VectorBase - mz), m_KeArm64VectorBase_size);
  if ( m_PsAltSystemCallHandlers != NULL )
    printf("PsAltSystemCallHandlers: %p, size %X\n", PVOID(m_PsAltSystemCallHandlers - mz), m_PsAltSystemCallHandlers_size);
}

struct range_item
{
  UINT64 addr;
  DWORD size;
  DWORD pad;   // perhaps size is also UINT64
};

int ntoskrnl_hack::try_find_PsKernelRangeList(PBYTE mz)
{
  // get .data section
  const one_section *where = m_pe->find_section_by_name(".data");
  if ( where == NULL )
    return 0;
  const BYTE sign[] = { 0x08, 0x03, 0x0, 0x0, 0x80, 0xF7, 0xFF, 0xFF, // FFFFF78000000308 - address of KUSER_SHARED_DATA.SystemCall
                        0x4, 0, 0, 0                                  // size - 4
                      };
  PBYTE start = mz + where->va;
  PBYTE end = start + where->size - sizeof(sign);
  bm_search srch((const PBYTE)sign, sizeof(sign));
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
  if ( 1 != founds.size() ) // wtf?
  {
    for ( auto citer = founds.cbegin(); citer != founds.cend(); ++citer )
      printf("possibly %p\n", PVOID(*citer - mz));
    return 0;
  }
  curr = *(founds.cbegin());
#ifdef _DEBUG
  printf("PsKernelRangeList: %p\n", PVOID(curr - mz));
#endif /* _DEBUG */
  // check backward
  range_item *r = (range_item *)curr;
  curr = (PBYTE)(r[-1].addr);
  if ( (curr >= start && curr < end) &&
       (r[-1].size == 1)
     )
    m_KdpBootedNodebug = curr;
  else
    return 0;
  // -2
  m_PspSystemMitigationOptions = (PBYTE)(r[-2].addr);
  m_PspSystemMitigationOptions_size = r[-2].size;
  // -3
  m_PsWin32NullCallBack =  (PBYTE)(r[-3].addr);
  m_PsWin32NullCallBack_size = r[-3].size;
  // -4 - can be null
  if ( r[-4].addr )
  {
    m_HvcallCodeVa = (PBYTE)(r[-4].addr);
    m_HvcallCodeVa_size = r[-4].size;
  }
  // -13
  m_PspPicoProviderRoutines = (PBYTE)(r[-13].addr);
  m_PspPicoProviderRoutines_size = r[-13].size;
  // check forward
  r += 3; // skip current and two next
  // KiDynamicTraceCallouts in ALMOSTRO?
  m_KiDynamicTraceCallouts = (PBYTE)(r[0].addr);
  if ( !in_section(m_KiDynamicTraceCallouts, "ALMOSTRO") )
  {
    m_KiDynamicTraceCallouts = NULL;
    return 1;
  }
  m_KiDynamicTraceCallouts_size = r[0].size;
  // some unnamed address in .data
  PBYTE unnamed = (PBYTE)(r[1].addr);
  if ( !in_section(unnamed, ".data") )
    return 0;
  // BBTBuffer in .data?
  m_BBTBuffer = (PBYTE)(r[2].addr);
  if ( !in_section(m_BBTBuffer, ".data") )
  {
    m_BBTBuffer = NULL;
    return 1;
  }
  m_BBTBuffer_size = r[2].size;
  // KeArm64VectorBase in CFGRO?
  m_KeArm64VectorBase = (PBYTE)(r[3].addr);
  if ( !in_section(m_KeArm64VectorBase, "CFGRO") )
  {
    m_KeArm64VectorBase = NULL;
    return 1;
  }
  m_KeArm64VectorBase_size = r[3].size;
  // HvlSmcException. size must be 0x200
  if ( NULL == r[4].addr || 0x200 != r[4].size )
    return 1;
  // PsAltSystemCallHandlers in ALMOSTRO?
  m_PsAltSystemCallHandlers = (PBYTE)(r[5].addr);
  if ( !in_section(m_PsAltSystemCallHandlers, "ALMOSTRO") )
  {
    m_PsAltSystemCallHandlers = NULL;
    return 1;
  }
  m_PsAltSystemCallHandlers_size = r[5].size;
  return 1;
}
