#pragma once

#include "dict.h"

struct export_item
{
  const char *name;
  BOOLEAN forwarded;
  WORD  ordinal;
  DWORD rva;
};

class exports_dict
{
  public:
   exports_dict();
  ~exports_dict();
   // methods for filling - return 0 if all o`k
   int alloc(size_t total, size_t strings_size);
   int finalize();
   inline struct export_item *items()
   {
     return (struct export_item *)m_ptr;
   }
   inline size_t total()
   {
     return m_total;
   }
   char *get_names_buffer() const;
   // find by ordinal
   const export_item *find(WORD) const;
   // find by name
   const export_item *find(const char *) const;
   // find nearest exported symbol by RVA
   const export_item *find_nearest(DWORD rva, DWORD &next_off) const;
   // find exact match by RVA
   const export_item *find_exact(DWORD rva) const;
   // for merging with SDT for ntoskrnl
   size_t merge_with_ssdt(const std::map<DWORD, const char *> *names, DWORD limit, PBYTE *sdt);
   // for merging with win32k.sys system call table
   size_t merge_with_win32k(const char *const *names, DWORD va, size_t tab_size, PDWORD sct);
   // for merging with some named table of ptrdiffs
   size_t merge_with_named_ptrdiffs(const char *const *names, ptrdiff_t *tab, size_t tab_size);
   // for debug
   void dump() const;
   PVOID mz;
   DWORD export_name;
  protected:
   size_t merge_with(std::map<DWORD, export_item> *);

   size_t m_total;
   size_t m_named;
   struct export_item **m_ords;
   struct export_item **m_names;
   char *m_ptr;
   // for merged data
   struct export_item *m_merged;
   size_t m_merged_total;
};
