#include "stdafx.h"
#include "pe_file.h"

one_export::one_export()
{
  name = NULL;
  rva = 0;
  ordinal = 0;
  forwarded = 0;
}

one_export::~one_export()
{
  if ( name != NULL )
    free(name);
}

int export_address_table::init(DWORD size, DWORD start)
{
  m_start = start;
  m_size  = size;
  // check if we already filled
  if ( m_eat != NULL )
  {
    free(m_eat);
    m_eat = NULL;
  }
  if ( m_names != NULL )
  {
    free(m_names);
    m_names = NULL;
  }
  // alloc space
  m_eat = (PDWORD)calloc(size, sizeof(DWORD));
  if ( m_eat == NULL )
    return 0;
  m_names = (struct one_export **)calloc(size, sizeof(struct one_export *));
  if ( m_names == NULL )
    return 0;
  return 1;
}

export_address_table::~export_address_table()
{
  if ( m_eat != NULL )
    free(m_eat);
  if ( m_names != NULL )
    free(m_names);
}

arm64_pe_file::arm64_pe_file(const wchar_t *mod_name)
{
  m_name = mod_name;
  m_mz = NULL;
  m_fp = NULL;
}

arm64_pe_file::~arm64_pe_file()
{
  if ( m_fp != NULL )
    fclose(m_fp);
  clean_exports();
}

const one_section *arm64_pe_file::find_section_rva(DWORD addr) const
{
  for ( auto iter = m_sects.cbegin(); iter != m_sects.cend(); ++iter )
  {
    DWORD end = iter->va + iter->size;
    if ( addr >= iter->va &&
         addr < end )
     return &*iter;
  }
  return NULL;
}

void arm64_pe_file::clean_exports()
{
  std::map<WORD, struct one_export *>::iterator iter = m_eords.begin();
  while( iter != m_eords.end() )
  {
    delete iter->second;
    ++iter;
  }
}

int arm64_pe_file::read(int dump_sects)
{
  _wfopen_s(&m_fp, m_name.c_str(), L"rb");
  if ( m_fp == NULL )
  {
    fprintf(stderr, "cannot open %S, error %d\n", m_name.c_str(), ::GetLastError());
    return -1;
  }
  char mz_bytes[2] = { 0, 0 };
  fread(mz_bytes, 2, 1, m_fp);
  if ( mz_bytes[0] != 'M' ||
       mz_bytes[1] != 'Z'
     )
    return -2;
  // get offset to PE
  m_pe_off = 0;
  fseek(m_fp, 0x3C, SEEK_SET);
  if ( 1 != fread(&m_pe_off, 4, 1, m_fp) )
    return -3;
  // read IMAGE_NT_HEADERS64
  fseek(m_fp, m_pe_off, SEEK_SET);
  fread(&m_hdr64, sizeof(m_hdr64), 1, m_fp);
  if ( m_hdr64.Signature != IMAGE_NT_SIGNATURE )
    return -4;
  // dump 
  printf("Machine: %X\n", m_hdr64.FileHeader.Machine);
  // from https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
  // IMAGE_FILE_MACHINE_ARM64 0xaa64
  if ( m_hdr64.FileHeader.Machine != 0xaa64 )
    return -5;
  // read sections
  // read all sections hdrs
  IMAGE_SECTION_HEADER sh;
  one_section s;
  DWORD i;
  for ( i = 0; i < m_hdr64.FileHeader.NumberOfSections; i++ )
  {
    fread(&sh, sizeof(sh), 1, m_fp);
    s.va     = sh.VirtualAddress;
    s.vsize  = sh.Misc.VirtualSize;
    s.offset = sh.PointerToRawData;
    s.size   = sh.SizeOfRawData;
    s.flags  = sh.Characteristics;
    memcpy(s.name, sh.Name, IMAGE_SIZEOF_SHORT_NAME);
    s.name[IMAGE_SIZEOF_SHORT_NAME] = 0;
    try
    {
      m_sects.push_back(s);
    } catch(std::bad_alloc)
    {  return -6; }
    if ( dump_sects )
    {
      printf("%s: VA %X, VSize %X, size %X, offset %X flags %X\n",
       s.name,
       sh.VirtualAddress,
       sh.Misc.VirtualSize,
       sh.SizeOfRawData,
       sh.PointerToRawData,
       sh.Characteristics
      );
    }
  }
  return 0;
}

char *arm64_pe_file::read_ename(DWORD rva)
{
  const struct one_section *os = find_section_rva(rva);
  if ( os == NULL )
    return NULL;
  DWORD pos = os->offset + rva - os->va;
  fseek(m_fp, pos, SEEK_SET);
  // 1) lets calc symbol length
  int len = 0;
  char c;
  do
  {
    c = (char)fgetc(m_fp);
    if ( c )
      len++;
    else
      break;
  } while ( !feof(m_fp) );
  if ( !len )
    return NULL;
  char *res = (char *)malloc(len + 1);
  fseek(m_fp, pos, SEEK_SET);
  fread(res, len, 1, m_fp);
  res[len] = 0;
  return res;
}

PBYTE arm64_pe_file::read_relocs(DWORD &rsize)
{
  DWORD raddr = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  rsize = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  if ( !raddr || !rsize )
    return NULL;
  const struct one_section *os = find_section_rva(raddr);
  if ( os == NULL )
    return NULL;
  fseek(m_fp, os->offset + raddr - os->va, SEEK_SET);
  // alloc enough memory
  PBYTE res = (PBYTE)malloc(rsize);
  if ( NULL == res )
    return NULL;
  if ( 1 != fread(res, rsize, 1, m_fp) )
  {
    free(res);
    return NULL;
  }
  return res;
}

int arm64_pe_file::read_exports()
{
  if ( m_eords.size() ||
       m_enames.size()
     )
    return 0; // already readed ?
  DWORD eaddr = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  DWORD esize = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if ( !eaddr )
    return 0;
  IMAGE_EXPORT_DIRECTORY edir;
  const struct one_section *os = find_section_rva(eaddr);
  if ( os == NULL )
    return -4;
  fseek(m_fp, os->offset + eaddr - os->va, SEEK_SET);
  fread(&edir, sizeof(edir), 1, m_fp);
  // check if we really have some export
  if ( !edir.NumberOfFunctions )
    return 0;
  // validate fields
  if ( edir.AddressOfFunctions != NULL )
  {
    const one_section *probe = find_section_rva(edir.AddressOfFunctions);
    if ( NULL == probe )
      return 0;
  }
  if ( edir.AddressOfNameOrdinals != NULL )
  {
    const one_section *probe = find_section_rva(edir.AddressOfNameOrdinals);
    if ( NULL == probe )
      return 0;
    // 18 Apr 2012 - lets check that all NumberOfFunctions can fit into this section
    unsigned __int64 ord_size = edir.NumberOfFunctions * sizeof(WORD);
    if ( ord_size > UINT_MAX )
      return -7;
    DWORD remaining_space = probe->size - (edir.NumberOfNames - probe->va);
    if ( remaining_space < ord_size )
      return -7;
  }
  if ( edir.AddressOfNames != NULL )
  {
    const one_section *probe = find_section_rva(edir.AddressOfNames);
    if ( NULL == probe )
      return 0;
  }
  m_exp_base = edir.Base;
  // read arrays of ordinals/names/RVAs
  PDWORD names = NULL;
  if ( edir.NumberOfNames )
  {
    names = (PDWORD)malloc( edir.NumberOfNames * sizeof(DWORD) );
    if ( names == NULL )
      return -5;
  }
  dumb_free_ptr d1(names);
  PWORD ords = (PWORD)malloc( edir.NumberOfFunctions * sizeof(WORD) );
  if ( ords == NULL )
  {
    return -5;
  }
  dumb_free_ptr d2(ords);
  int eat_inited = m_eat.init(edir.NumberOfFunctions, edir.AddressOfFunctions);
  // check if all alloced
  if ( !eat_inited )
    return -5;
  // rvas
  os = find_section_rva(edir.AddressOfFunctions);
  if ( os == NULL )
    return -5;
  fseek(m_fp, os->offset + edir.AddressOfFunctions - os->va, SEEK_SET);
  fread(m_eat.m_eat, edir.NumberOfFunctions * sizeof(DWORD), 1, m_fp);
  // names
  if ( names != NULL )
  {
    os = find_section_rva(edir.AddressOfNames);
    if ( os == NULL )
      return -5;
    fseek(m_fp, os->offset + edir.AddressOfNames - os->va, SEEK_SET);
    fread(names, edir.NumberOfNames * sizeof(DWORD), 1, m_fp);
  }
  // ordinals
  DWORD i;
  WORD ord;
  if ( edir.AddressOfNameOrdinals )
  {
    os = find_section_rva(edir.AddressOfNameOrdinals);
    if ( os == NULL )
      return -5;
    fseek(m_fp, os->offset + edir.AddressOfNameOrdinals - os->va, SEEK_SET);
    fread(ords, edir.NumberOfNames * sizeof(WORD), 1, m_fp);
  } else {
    for ( i = 0; i < edir.NumberOfFunctions; i++ )
      ords[i] = (WORD)(i + m_exp_base);
  }
  // cewl, lets fill our dicts
  std::map<WORD, struct one_export *>::const_iterator find_iter;
  struct one_export *oe;
  for ( i = 0; i < edir.NumberOfNames; i++ )
  {
    ord = ords[i];
    if ( ord >= edir.NumberOfFunctions )
      continue;
    if ( !m_eat.m_eat[ord] )
      continue;
    // check if we already inserted such ordinal
    find_iter = m_eords.find((WORD)(ord + m_exp_base));
    if ( find_iter != m_eords.end() )
       continue;
    try
    {
      oe = new one_export;
    } catch(std::bad_alloc)
    {
      oe = NULL;
    }
    if ( oe == NULL )
    {
      continue;
    }
    if ( i < edir.NumberOfNames )
    {
      oe->name = read_ename(names[i]);
      if ( oe->name != NULL )
        m_exports_total_size += strlen(oe->name) + 1;
    }
    oe->rva = m_eat.m_eat[ord];
    oe->ordinal = (WORD)(ord + m_exp_base);
    // check for forwarded export - algo from http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
    if ( (oe->rva >= eaddr) &&
         (oe->rva < (eaddr + esize))
       )
      oe->forwarded = 1;
    m_eat.m_names[ord] = oe;
    if ( oe->name != NULL )
    {
      try
      {
        m_enames[oe->name] = oe;
      } catch(std::bad_alloc)
      {}
    }
    try
    {
      m_eords[oe->ordinal] = oe;
    } catch(std::bad_alloc)
    {}
  }
  // we need also second pass to fill all nonamed functions
  for ( i = 0; i < edir.NumberOfFunctions; i++ )
  {
    if ( m_eat.m_names[i] != NULL )
      continue;
    if ( !m_eat.m_eat[i] )
      continue;
    try
    {
      oe = new one_export;
    } catch(std::bad_alloc)
    {
      oe = NULL;
    }
    if ( oe == NULL )
    {
      continue;
    }
    m_eat.m_names[i] = oe;
    oe->rva = m_eat.m_eat[i];
    oe->ordinal = (WORD)(i + m_exp_base);
    if ( (oe->rva >= eaddr) &&
         (oe->rva < (eaddr + esize))
       )
      oe->forwarded = 1;
    // insert to ordinals
    try
    {
      m_eords[oe->ordinal] = oe;
    } catch(std::bad_alloc)
    {}
  }
  return 0;
}

exports_dict *arm64_pe_file::get_export_dict()
{
  if ( read_exports() )
    return NULL;
  exports_dict *res = NULL;
  try
  {
    res = new exports_dict;
  } catch(std::bad_alloc)
  { return NULL; }
  if ( res == NULL )
   return NULL;
  size_t ords_count    = m_eords.size();
  if ( res->alloc(ords_count, m_exports_total_size) )
  {
    delete res;
    return NULL;
  }
  // fill export_item
  std::map<WORD, struct one_export *>::iterator iter = m_eords.begin();
  char *exp_names = res->get_names_buffer();
  char *current_name;
  struct export_item *item = res->items();
  for ( size_t index = 0; iter != m_eords.end(); ++iter, index++  )
  {
    if ( iter->second->name != NULL )
    {
      // 1) copy one_export to export_item
      item[index].name = exp_names;
      for ( current_name = iter->second->name; ; current_name++ )
      {
        *exp_names = *current_name;
        exp_names++;
        if ( !*current_name )
          break;
      }
    } else
      item[index].name = NULL;
    item[index].forwarded = iter->second->forwarded;
    item[index].ordinal   = iter->second->ordinal;
    item[index].rva       = iter->second->rva;
  }
  if ( res->finalize() )
  {
    delete res;
    return NULL;
  }
  return res;
}
