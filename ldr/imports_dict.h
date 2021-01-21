#pragma once

#include "dict.h"
#include "imp_tab.h"
#include "imports_dict.h"
#include "pe_file.h"

struct import_item
{
  const char *modname;
  const char *name; // == NULL if need use ordinal. 
                    // Don`t free this field - all names will be killed during import_holder destruction
  WORD  ordinal;
};

class module_import
{
  public:
    module_import()
    {
      iat_count = iat_rva = 0;
      iat_size = 0;
      iat = NULL;
    }
   ~module_import()
    {
      if ( iat != NULL )
        free(iat);
    }
   DWORD iat_rva;
   DWORD iat_size;
   DWORD iat_count;
   struct import_item *iat;  
};

class import_holder_intf
{
  public:
   import_holder_intf()
    : m_modules(NULL),
      m_names(NULL)
   {}
   virtual ~import_holder_intf();
   virtual module_import *find(const wchar_t *) const;
   virtual module_import *get(PVOID &, const wchar_t **) const;
   inline size_t names_count() const
   {
     if ( m_names == NULL )
       return 0;
     return dict_count(m_names);
   }
   inline size_t modules_count() const
   {
     if ( m_modules == NULL )
       return 0;
     return dict_count(m_modules);
   }
  protected:
   void kill_dicts();

   dict_t *m_modules; // key - name of module, value - module_import
   dict_t *m_names;   // key - name of function
};

class inmem_import_holder: public import_holder_intf
{
  public:
   inmem_import_holder();
   inmem_import_holder(inmem_import_holder &&outer)
   {
     m_modules = outer.m_modules;
     outer.m_modules = NULL;
     m_names = outer.m_modules;
     outer.m_names = NULL;
   }
  ~inmem_import_holder();
   module_import *add(const wchar_t *, arm64_pe_file *);
   module_import *add_delayed(const wchar_t *, arm64_pe_file *);
  protected:
   void fill_import(PBYTE mz, pIMPORT_DIRECTORY_ENTRY, DWORD size, module_import *);
   void fill_delayed(PBYTE mz, PDELAYEDIMPORT_DIRECTORY_ENTRY, DWORD size, module_import *);
   DWORD get_import_size(PBYTE mz, pIMPORT_DIRECTORY_ENTRY, DWORD size, DWORD *min_addr);
   DWORD get_delayed_size(PBYTE mz, PDELAYEDIMPORT_DIRECTORY_ENTRY, DWORD size, DWORD *min_addr);
   DWORD calc_iat_size(PBYTE);
};
