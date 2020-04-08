#pragma once

#include "exports_dict.h"
#include "load_config.h"

/* Standart PE relocation thunk */
typedef struct _RELOC {
  WORD   Offset : 12;
  WORD   Type   : 04;
} RELOC, *PRELOC;

// for auto free
struct dumb_free_ptr
{
  dumb_free_ptr()
  {
    m_ptr = NULL;
  }
  dumb_free_ptr(void *arg)
    : m_ptr(arg)
  { }
  ~dumb_free_ptr()
  {
    if ( m_ptr != NULL )
      free(m_ptr);
  }
  void operator=(void *arg)
  {
    if ( (m_ptr != NULL) && (m_ptr != arg) )
      free(m_ptr);
    m_ptr = arg;
  }
  void reset()
  {
    m_ptr = NULL;
  }
 protected:
  void *m_ptr;
};

struct one_export
{
  one_export();
 ~one_export();

  char *name;
  WORD ordinal;
  DWORD rva;
  int forwarded;
};

struct export_address_table
{
  export_address_table()
   : m_size(0),
     m_start(0),
     m_eat(NULL),
     m_names(NULL)
  {}
 ~export_address_table();
  int init(DWORD size, DWORD start);

  DWORD  m_size;
  DWORD  m_start;
  PDWORD m_eat;
  struct one_export **m_names;
};

struct one_section
{
  DWORD va;
  DWORD vsize;
  DWORD offset;
  DWORD size;
  DWORD flags;
  char name[IMAGE_SIZEOF_SHORT_NAME + 1];
};

// dirty hacks for export names
struct export_name
{
  export_name(export_name const& s)
  {
    name = s.name;
  }
  export_name(const char *str)
  {
    name = str;
  }
  bool operator<(const export_name& s) const
  {
    return (strcmp(name, s.name) < 0);
  }
  bool operator==(const export_name& s) const
  {
    return (0 == strcmp(name, s.name));
  }

  const char *name;
};

class arm64_pe_file
{
  public:
    arm64_pe_file(const wchar_t *mod_name);
   ~arm64_pe_file();
    int read(int with_dump);
    inline DWORD entry_point() const
    {
      return m_hdr64.OptionalHeader.AddressOfEntryPoint;
    }
   // exports
   inline DWORD export_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
   }
   inline DWORD export_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
   }
   inline int get_export(DWORD &addr, DWORD &size) const
   {
      return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_EXPORT);
   }
   // imports
   inline DWORD import_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
   }
   inline DWORD import_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
   }
   int get_import(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_IMPORT);
   }
   // delayed imports
   inline DWORD delayed_import_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
   }
   inline DWORD delayed_import_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
   }
   int get_delayed_import(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
   }
   // bound imports
   inline DWORD bound_import_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
   }
   inline DWORD bound_import_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
   }
   int get_bound_import(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
   }
   // for resources
   inline DWORD rsrc_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
   }
   inline DWORD rsrc_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
   }
   int get_rsrc(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_RESOURCE);
   }
   // security
   inline DWORD security_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
   }
   inline DWORD security_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
   }
   int get_security(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_SECURITY);
   }
   // relocs
   inline DWORD rel_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
   }
   inline DWORD rel_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
   }
   int get_rel(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_BASERELOC);
   }
   // arch
   inline DWORD arch_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress;
   }
   inline DWORD arch_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;
   }
   int get_arch(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
   }
   // GLOBALPTR
   inline DWORD gp_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress;
   }
   inline DWORD gp_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size;
   }
   int get_gp(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_GLOBALPTR);
   }
   // for TLS
   inline DWORD tls_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
   }
   inline DWORD tls_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
   }
   int get_tls(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_TLS);
   }
   // for IAT
   inline DWORD iat_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
   }
   inline DWORD iat_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
   }
   int get_iat(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_IAT);
   }
   // load config
   inline DWORD load_config_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
   }
   inline DWORD load_config_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
   }
   inline int get_load_config(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
   }
   // exceptions
   inline DWORD exceptions_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
   }
   inline DWORD exceptions_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
   }
   inline int get_exceptions(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
   }
   // .NET
   inline DWORD net_addr() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
   }
   inline DWORD net_size() const
   {
     return m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
   }
   inline int get_net(DWORD &addr, DWORD &size) const
   {
     return get_xxx(addr, size, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
   }
   // other fields
   inline PBYTE base_addr() const
   {
     return m_mz;
   }
   inline ULONGLONG image_base() const
   {
     return m_hdr64.OptionalHeader.ImageBase;
   }
   const one_section *find_section_rva(DWORD addr) const;
   // exports
   exports_dict *get_export_dict();
   // read relocs
   PBYTE read_relocs(DWORD &rsize);
   // load config
   PBYTE read_load_config(DWORD &readed);
   void dump_rfg_relocs();
  protected:
    inline int get_xxx(DWORD &addr, DWORD &size, int idx) const
    {
      addr = m_hdr64.OptionalHeader.DataDirectory[idx].VirtualAddress;
      size = m_hdr64.OptionalHeader.DataDirectory[idx].Size;
      return (addr && size);
    }
    inline DWORD align_size(DWORD size)
    {
      return (size + 0xfff) & ~0xfff;
    }
    int read_exports();
    char *read_ename(DWORD rva);
    void clean_exports();

    std::wstring m_name;
    std::list<one_section> m_sects;
    PBYTE m_mz;
    FILE *m_fp;
    IMAGE_NT_HEADERS64 m_hdr64;
    DWORD m_pe_off;    
    // exports
    DWORD m_exp_base; // ordinal base
    std::map<export_name, struct one_export *> m_enames;
    std::map<WORD, struct one_export *> m_eords;
    size_t m_exports_total_size;
    // EAT
    export_address_table m_eat;
    // load config
    DWORD m_lc_readed;
    rfg_IMAGE_LOAD_CONFIG_DIRECTORY64 m_lc;
};