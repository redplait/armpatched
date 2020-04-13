#include "stdafx.h"
#include "exports_dict.h"
#include <search.h>

/**** exports_dict implementation ****/
exports_dict::exports_dict()
{
  m_total = m_named = m_merged_total = 0;
  m_ords = m_names = NULL;
  m_ptr = NULL;
  m_merged = NULL;
  mz = NULL;
  export_name = 0;
}

exports_dict::~exports_dict()
{
  if ( m_ptr != NULL )
    free(m_ptr);
  if ( m_merged != NULL )
    free(m_merged);
}

int exports_dict::alloc(size_t total, size_t strings)
{
  m_total = total;
  if ( m_ptr != NULL )
  {
    free(m_ptr);
    m_ptr = NULL;
  }
  m_ords = m_names = NULL;
  // calc total size
  size_t alloc = m_total * sizeof(export_item) + 
                 2 * m_total * sizeof(export_item *) +
                 strings;
  if ( !alloc )
    return -2;
  m_ptr = (char *)malloc(alloc);
  if ( m_ptr == NULL )
    return -1;
  // assing pointers
  m_names = (struct export_item **)(m_ptr + m_total * sizeof(export_item));
  m_ords  = (struct export_item **)(m_ptr + m_total * sizeof(export_item) + m_total * sizeof(export_item *));
  return 0;
}

char *exports_dict::get_names_buffer() const
{
  return m_ptr +
         m_total * sizeof(export_item) + // items        
         2 * m_total * sizeof(export_item *) // ord items (*) + named items (*)
  ;
}

static int __cdecl cmp_rva(const void *a, const void *b)
{
  const export_item *aa = (const export_item *)a,
                    *bb = (const export_item *)b;
  return aa->rva - bb->rva;
}

static int __cdecl cmp_ord_items(const void *a, const void *b)
{
  const export_item **aa = (const export_item **)a,
                    **bb = (const export_item **)b;
  return (*aa)->ordinal - (*bb)->ordinal;
}

static int __cdecl cmp_names_items(const void *a, const void *b)
{
  const export_item **aa = (const export_item **)a,
                    **bb = (const export_item **)b;
  return strcmp((*aa)->name, (*bb)->name);
}

void exports_dict::dump() const
{
  size_t count = m_total;
  struct export_item *items = (struct export_item *)m_ptr;
  if ( m_merged != NULL )
  {
    items = m_merged;
    count = m_merged_total;
  }
  if ( !count )
    return;
  for ( size_t i = 0; i < count; i++, items++ )
  {
    if ( items->name != NULL )
      printf("Ord %d %d %X %s\n", items->ordinal, 
        items->forwarded, items->rva, items->name
      );
    else
      printf("Ord %d %d %X\n", items->ordinal, items->forwarded, items->rva);
  }
}

int exports_dict::finalize()
{
  // 1) sort exported items on rva
  if ( !m_total )
    return -1;
  struct export_item *items = (struct export_item *)m_ptr;
  qsort(items, m_total, sizeof(export_item), cmp_rva);
  // 2) fill named items
  size_t i, index;
  for ( index = i = 0; i < m_total; i++ )
  {
    if ( (items[i].name != NULL) &&
         items[i].name[0]
       )
    {
      m_names[index] = &items[i];
      index++;
    }
  }
  m_named = index;
  if ( m_named )
    qsort(m_names, m_named, sizeof(export_item *), cmp_names_items);
  // 3) fill ords
  for ( i = 0; i < m_total; i++ )
  {
    m_ords[i] = &items[i];
  }
  qsort(m_ords, m_total, sizeof(export_item *), cmp_ord_items);
  return 0;
}

static int __cdecl find_ord(const void *key, const void *elem)
{
  const export_item **aa = (const export_item **)elem;
  if ( (WORD)key < (*aa)->ordinal )
    return -1;
  if ( (WORD)key > (*aa)->ordinal )
    return 1;
  return 0;
}

static int __cdecl find_name(const void *key, const void *elem)
{
  const export_item **aa = (const export_item **)elem;
  return strcmp((const char *)key, (*aa)->name);
}

const export_item *exports_dict::find(WORD ord) const
{
  const export_item **item = (const export_item **)
    bsearch((const void *)ord, m_ords, m_total, sizeof(export_item *), find_ord);
  if ( item == NULL )
    return NULL;
  return *item;
}

const export_item *exports_dict::find(const char *name) const
{
  if ( !m_named )
    return NULL;
  const export_item **item = (const export_item **)
    bsearch((const void *)name, m_names, m_named, sizeof(export_item *), find_name);
  if ( item == NULL )
    return NULL;
  return *item;
}

static int __cdecl cmp_with_prev(const void *key, const void *elem)
{
  DWORD rva = (DWORD)key;
  const export_item *item = (const export_item *)elem;
  if ( rva < item->rva )
    return -1;
  if ( rva == item->rva )
    return 0;
  // inside some exported area
  if ( rva < item[1].rva )
    return 0;
  return 1;
}

const export_item *exports_dict::find_nearest(DWORD rva, DWORD &next_off) const
{
  next_off = 0;
  size_t count = m_total;
  struct export_item *items = (struct export_item *)m_ptr;
  if ( m_merged != NULL )
  {
    items = m_merged;
    count = m_merged_total;
  }
  if ( !count )
    return NULL;
  // 1) check for first
  if ( rva < items[0].rva )
  {
    next_off = items[0].rva;
    return NULL;
  }
  // 2) check last
  if ( rva >= items[count - 1].rva )
  {
    next_off = 0xffffffff;
    return &items[count - 1];
  }
  // 3) lets find
  const export_item *item = (const export_item *)
    bsearch((const void *)rva, items, count - 1, sizeof(export_item), cmp_with_prev);
  if ( item != NULL )
  {
    // check if next export has the same addr (when same addr has several exported names)
    size_t remained = items + count - item;
    size_t i = 1;
    for ( ; i < remained; i++, item++ )
    {
      if ( item[1].rva == rva )
        continue;
      next_off = item[1].rva;
      break;
    }
    // check case when all symbols at end are at the same address
    if ( i == remained )
      next_off = 0xffffffff;
  }
  return item;
}

static int __cdecl cmp_rvas(const void *key, const void *elem)
{
  DWORD rva = (DWORD)key;
  const export_item *item = (const export_item *)elem;
  if ( rva < item->rva )
    return -1;
  if ( rva == item->rva )
    return 0;
  return 1;
}

const export_item *exports_dict::find_exact(DWORD rva) const
{
  struct export_item *items = (struct export_item *)m_ptr;
  size_t count = m_total;
  // check already merged
  if ( m_merged != NULL )
  {
    items = m_merged;
    count = m_merged_total;
  }
  if ( !count )
    return NULL;
  return (const export_item *)bsearch(
    (const void *)rva, items, count, sizeof(export_item), cmp_rvas
  );
}

size_t exports_dict::merge_with(std::map<DWORD, export_item> *func2add)
{
  size_t new_count = func2add->size();
  if ( !new_count )
    return 0;
  size_t index;
  std::map<DWORD, export_item>::iterator fiter;
  new_count += (m_merged != NULL) ? m_merged_total : m_total;
  export_item *res = (export_item *)malloc(sizeof(export_item) * new_count);
  if ( NULL == res )
    return NULL;
  // copy old content
  if ( m_merged != NULL )
  {
    memcpy(res, m_merged, sizeof(export_item) * m_merged_total);
    index = m_merged_total;
  } else {
    memcpy(res, m_ptr, sizeof(export_item) * m_total);
    index = m_total;
  }
  // fill added entries
  for ( fiter = func2add->begin();
        fiter != func2add->end();
        fiter++, index++
      )
  {
    res[index] = fiter->second;
  }
  // swap res to m_merged
  if ( m_merged != NULL )
    free(m_merged);
  m_merged = res;
  m_merged_total = new_count;
  // and finally sort
  qsort(m_merged, m_merged_total, sizeof(export_item), cmp_rva);
  // return count of added functions
  return func2add->size();
}

size_t exports_dict::merge_with_named_ptrdiffs(const char *const *names, ptrdiff_t *tab, size_t tab_size)
{
  std::map<DWORD, export_item> func2add;
  std::map<DWORD, export_item>::iterator fiter;
  export_item item;
  size_t index;
  for ( index = 0; index < tab_size; index++ )
  {
    const export_item *ei = find_exact(tab[index]);
    if ( ei != NULL )
      continue;
    // check if we already add this addr
    fiter = func2add.find(tab[index]);
    if ( fiter != func2add.end() )
      continue;
    // lets add
    item.name = names[index];
    item.rva = tab[index];
    item.ordinal = 0;
    item.forwarded = FALSE;
    try
    {
      func2add[tab[index]] = item;
    } catch(std::bad_alloc)
    {
    }
  }
  return func2add.empty() ? 0 : merge_with(&func2add);
}

size_t exports_dict::merge_with_win32k(const char *const *names, DWORD va, size_t tab_size, PDWORD sct)
{
  std::map<DWORD, export_item> func2add;
  std::map<DWORD, export_item>::iterator fiter;
  export_item item;
  size_t index;
  DWORD rva;
  for ( index = 0; index < tab_size; index++ )
  {
    rva = (DWORD)(sct[index] - va);
    // check if we already has this RVaddr
    const export_item *ei = find_exact(rva);
    if ( ei != NULL )
      continue;
    // check if we already add this addr
    fiter = func2add.find(rva);
    if ( fiter != func2add.end() )
      continue;
    // lets add
    item.name = names[index];
    item.rva = rva;
    item.ordinal = 0;
    item.forwarded = FALSE;
    try
    {
      func2add[rva] = item;
    } catch(std::bad_alloc)
    {
    }
  }
  return func2add.empty() ? 0 : merge_with(&func2add);
}

size_t exports_dict::merge_with_ssdt(const std::map<DWORD, const char *> *names, DWORD limit, PBYTE *sdt)
{
  std::map<DWORD, export_item> func2add;
  std::map<DWORD, export_item>::iterator fiter;
  std::map<DWORD, const char *>::const_iterator iter;
  export_item item;
  size_t index;
  DWORD rva;
  for ( index = 0; index < limit; index++ )
  {
    rva = (DWORD)sdt[index];
    // 0) check if this entry has name
    iter = names->find((DWORD)index);
    if ( iter == names->end() )
      continue;
    // 1) check if we already have this addr
    const export_item *ei = find_exact(rva);
    if ( ei != NULL )
      continue;
    // 2) check if we already add this addr
    fiter = func2add.find(rva);
    if ( fiter != func2add.end() )
      continue;
    // 3) lets add
    item.name = iter->second;
    item.rva = rva;
    item.ordinal = 0;
    item.forwarded = FALSE;
    try
    {
      func2add[rva] = item;
    } catch(std::bad_alloc)
    {
    }
  }
  // lets see if we really need to add something
  return func2add.empty() ? 0 : merge_with(&func2add);
}
