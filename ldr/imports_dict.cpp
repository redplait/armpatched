#include "stdafx.h"
#include "imports_dict.h"

//
// import_holder_intf implementation
//
static int cmp2names(const void *a, const void *b)
{
  return strcmp((const char *)a, (const char *)b);
}

static int cmp2modnames(const void *a, const void *b)
{
  return _wcsicmp((const wchar_t *)a, (const wchar_t *)b);
}

static void kill_names(dnode_t *node, void *unused)
{
  if ( node != NULL )
  {
    char *name = (char *)dnode_getkey(node);
    if ( name != NULL )
      free(name);
    free(node);
  }
}

static void kill_modules(dnode_t *node, void *unused)
{
  if ( node != NULL )
  {
    module_import *mi = (module_import *)dnode_get(node);
    if ( mi != NULL )
      delete mi;
    free(node);
  }
}

void import_holder_intf::kill_dicts()
{
  if ( m_modules != NULL )
  {
    dict_free(m_modules);
    dict_destroy(m_modules);
    m_modules = NULL;
  }
  if ( m_names != NULL )
  {
    dict_free(m_names);
    dict_destroy(m_names);
    m_names = NULL;
  }
}

import_holder_intf::~import_holder_intf()
{
  kill_dicts();
}

module_import *import_holder_intf::find(const wchar_t *modname) const
{
  if ( m_modules == NULL )
    return NULL;
  dnode_t *node = dict_lookup(m_modules, modname);
  if ( node == NULL )
    return NULL;
  return (module_import *)dnode_get(node);
}

module_import *import_holder_intf::get(PVOID &current, const wchar_t **out_name) const
{
  if ( m_modules == NULL )
    return NULL;
  dnode_t *node = (dnode_t *)current;
  if ( node == NULL )
  {
    node = dict_first(m_modules);
  } else {
    node = dict_next(m_modules, node);
  }
  if ( NULL == node )
    return NULL;
  current = node;
  if ( out_name != NULL )
    *out_name = (const wchar_t *)dnode_getkey(node);
  return (module_import *)dnode_get(node);
}

//
// inmem_import_holder implementation
//
inmem_import_holder::inmem_import_holder()
 : import_holder_intf()
{
  // create modules dictionary
  m_modules = dict_create(DICTCOUNT_T_MAX, cmp2modnames);
  dict_set_allocator(m_modules, NULL, kill_modules, NULL);
  // zero all remained
  m_pe = NULL;
}

inmem_import_holder::~inmem_import_holder()
{
}

DWORD inmem_import_holder::calc_iat_size(PBYTE ptr)
{
  DWORD size = 0;
  for ( ; *(PDWORD)ptr; ptr += 8 )
    size++;
  return 1 + size;
}

void inmem_import_holder::fill_import(pIMPORT_DIRECTORY_ENTRY pdde, DWORD size, module_import *mi)
{
  PBYTE mz = m_pe->base_addr();
  for ( pIMPORT_DIRECTORY_ENTRY de = pdde;
        ((PBYTE)de < ((PBYTE)pdde + size)) && de->AddressTableRVA && de->NameRVA;
        ++de
      )
  {
    DWORD rva = de->AddressTableRVA;
    DWORD index = rva - mi->iat_rva;
    DWORD lookup_rva = de->ImportLookUp;
    if ( !lookup_rva )
      lookup_rva = rva;
    index /= 8;
    const char *mod_name = (const char *)mz + de->NameRVA;
    PBYTE ptr = (PBYTE)mz + lookup_rva;
    for ( ; *(PDWORD)ptr; ptr += 8, index++ )
    {
      mi->iat[index].modname = mod_name;
      if ( *(unsigned __int64 *)ptr & IMAGE_ORDINAL_FLAG64 )
        mi->iat[index].ordinal = *(PDWORD)ptr & 0xffffffff;
      else {
        mi->iat[index].name = (const char *)((PBYTE)mz + 2 + *(PDWORD)ptr);
      }
    }
  }
}

DWORD inmem_import_holder::get_import_size(pIMPORT_DIRECTORY_ENTRY imp, DWORD size, DWORD *min_addr)
{
  PBYTE mz = m_pe->base_addr();
  *min_addr = NULL;
  DWORD iat_size = 0;
  DWORD max_addr = 0;
  pIMPORT_DIRECTORY_ENTRY de;
  pIMPORT_DIRECTORY_ENTRY max = NULL;
  for ( de = imp;
        ((PBYTE)de < ((PBYTE)imp + size)) && de->AddressTableRVA && de->NameRVA;
        ++de
      )
  {
    DWORD rva = de->AddressTableRVA;
    if ( !*min_addr )
    {
      *min_addr = rva;
      max_addr = rva;
      max = de;
    }
    else  
    {
      if ( rva < *min_addr )
       *min_addr = rva;
      if ( rva > max_addr )
      {
        max_addr = rva;
        max = de;
      }
    }
  }
  // so we now have min_iat & max_iat and also max - last iat descriptor
  iat_size = max_addr - *min_addr;
  iat_size /= 8;
  if ( max != NULL )
  {
    DWORD rva = max->AddressTableRVA;
    iat_size += calc_iat_size((PBYTE)mz + rva);
  }
  return iat_size;
}

module_import *inmem_import_holder::add(const wchar_t *modname, arm64_pe_file *pe)
{
  m_pe = pe;
  PBYTE mz = m_pe->base_addr();
  // check if we have import
  DWORD imp_rva = 0;
  DWORD imp_size = 0;
  if ( !m_pe->get_import(imp_rva, imp_size) )
    return NULL;
  // calc size of iat
  DWORD diat_min = 0;
  DWORD total_size = get_import_size((pIMPORT_DIRECTORY_ENTRY)((PBYTE)mz + imp_rva), imp_size, &diat_min);
  if ( !total_size )
    return NULL;
  // alloc module_import for return
  module_import *mi = NULL;
  try
  {
    mi = new module_import();
  } catch(std::bad_alloc)
  { }
  if ( mi == NULL )
    return NULL;
  // and fill it
  mi->iat_rva = diat_min;
  mi->iat_count = total_size;
  mi->iat_size = total_size * 8;
  mi->iat = (struct import_item *)calloc(mi->iat_count, sizeof(struct import_item));
  if ( mi->iat == NULL )
  {
    fprintf(stderr, "Cannot alloc %d bytes for imports\n", mi->iat_count * sizeof(struct import_item));
    delete mi;
    return NULL;
  }
  fill_import((pIMPORT_DIRECTORY_ENTRY)((PBYTE)mz + imp_rva), imp_size, mi);
  // insert this new module_import object into dictionary
  dict_alloc_insert(m_modules, modname, mi);
  return mi;  
}
