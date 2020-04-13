#pragma once

#include <pshpack1.h>
// standart pe import directory entry
typedef struct sIMPORT_DIRECTORY_ENTRY {
  DWORD  ImportLookUp;      // +00h       // offset of lookup table.
  DWORD  TimeDateStamp;     // +04h       // junk, usually 0.
  DWORD  ForwardChain;      // +08h       // junk, usually -1.
  DWORD  NameRVA;           // +0Ch       // rva of dll name.
  DWORD  AddressTableRVA;   // +10h       // rva of import address table.
} IMPORT_DIRECTORY_ENTRY, *pIMPORT_DIRECTORY_ENTRY;

typedef struct sImgDelayDescr
{
  DWORD grAttrs;
  DWORD szName;
  DWORD phmod;
  DWORD pIAT;
  DWORD pINT;
  DWORD pBoundIAT;
  DWORD pUnloadIAT;
  DWORD dwTimeStamp;
} DELAYED_IMPORT_DIRECTORY_ENTRY, *PDELAYEDIMPORT_DIRECTORY_ENTRY;
#include <poppack.h>
