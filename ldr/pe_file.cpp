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
  m_mz_size = 0;
  m_fp = NULL;
  m_lc_readed = 0;
  memset(&m_lc, 0, sizeof(m_lc));
}

arm64_pe_file::~arm64_pe_file()
{
  if ( m_mz != NULL )
    VirtualFree(m_mz, 0, MEM_RELEASE);
  if ( m_fp != NULL )
    fclose(m_fp);
  clean_exports();
}

const one_section *arm64_pe_file::find_section_by_name(const char *sname) const
{
  if ( sname == NULL )
    return NULL;
  for ( auto iter = m_sects.cbegin(); iter != m_sects.cend(); ++iter )
  {
    if ( !strcmp(iter->name, sname) )
     return &*iter;
  }
  return NULL;
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

const one_section *arm64_pe_file::find_section_v(DWORD addr) const
{
  for ( auto iter = m_sects.cbegin(); iter != m_sects.cend(); ++iter )
  {
    DWORD end = iter->va + iter->vsize;
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
      printf("[%X] %s: VA %X, VSize %X, size %X, offset %X flags %X\n", i,
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

PBYTE arm64_pe_file::read_load_config(DWORD &readed)
{
  if ( m_lc_readed )
  {
    readed = m_lc_readed;
    return (PBYTE)&m_lc;
  }
  DWORD addr = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
  DWORD size = m_hdr64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
  if ( !addr || !size )
    return NULL;
  const struct one_section *os = find_section_rva(addr);
  if ( os == NULL )
    return NULL;
  fseek(m_fp, os->offset + addr - os->va, SEEK_SET);
  size = min(size, sizeof(m_lc));
  m_lc_readed = (DWORD)fread(&m_lc, 1, size, m_fp);
  if ( !m_lc_readed )
    return NULL;
  readed = m_lc_readed;
  return (PBYTE)&m_lc;
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

int arm64_pe_file::apply_relocs()
{
  if ( m_mz == NULL ) 
    return 0;
  DWORD raddr = 0,
        rsize = 0;
  if ( !get_rel(raddr, rsize) )
    return 0;
  PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)(m_mz + raddr);
  PBYTE  RelEnd = ((PBYTE)BaseReloc + rsize);
  LONGLONG diff = (LONGLONG)m_mz - image_base();
  while ((PBYTE)BaseReloc < RelEnd && BaseReloc->SizeOfBlock)
  {
    PRELOC Reloc = (PRELOC)((PBYTE)BaseReloc + sizeof(IMAGE_BASE_RELOCATION));
    for ( DWORD i = 0;
          (i < (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC)) &&
          ((PBYTE)&Reloc[i] < RelEnd);
          i++
        )
    {
       if ( !Reloc[i].Type ) // I don`t know WTF is absolute reloc means
         continue;
       // see https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
       // 10 - IMAGE_REL_BASED_DIR64
       if ( Reloc[i].Type != 10 )
       {
          printf("unknown reltype %d offset %X\n", Reloc[i].Type, BaseReloc->VirtualAddress + Reloc[i].Offset);
          continue;
        }
        *(LONGLONG *)(m_mz + BaseReloc->VirtualAddress + Reloc[i].Offset) += diff;
    }
    BaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseReloc + BaseReloc->SizeOfBlock);
  }
  return 1;
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
  m_exp_name = edir.Name;
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
  res->export_name = m_exp_name;
  return res;
}

void arm64_pe_file::dump_rfg_relocs()
{
  // check if we have load_config and DynamicValueRelocTableOffset
  if ( m_lc_readed < offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset) )
    return;
  if ( !m_lc.DynamicValueRelocTableOffset)
    return;
  // yep, we have some RFG, find section where they located
  DWORD reloff = rel_addr();
  DWORD our_off = reloff + m_lc.DynamicValueRelocTableOffset;
  const struct one_section *os = find_section_rva(our_off);
  if ( os == NULL )
    return;
  DWORD version = 0;
  // check if rva has some content on disk
  if ( (reloff  + sizeof(DWORD)) > (os->va + os->size) )
     return;
  // seek and read version
  fseek(m_fp, os->offset + our_off - os->va, SEEK_SET);
  if ( 1 != fread(&version, sizeof(version), 1, m_fp) )
    return;
  printf("RFG version: %d\n", version);
  if ( 1 != version )
    return;
  DWORD size = 0;
  // read size of RFG relocs
  if ( 1 != fread(&size, sizeof(size), 1, m_fp) )
    return;
  printf("RFG size: %X\n", size);
  // alloc enough memory
  PBYTE data = (PBYTE)malloc(size);
  if ( data == NULL )
    return;
  dumb_free_ptr dumb(data);
  if ( 1 != fread(data, size, 1, m_fp) )
    return;
  // dump
  PBYTE data_end = data + size;
  PBYTE curr = data;
  // iterate on IMAGE_DYNAMIC_RELOCATION
  while( curr < data_end )
  {
    BYTE rel_type = *curr;
    if ( (rel_type > 5) || !rel_type )
    {
       printf("unknown IMAGE_DYNAMIC_RELOCATION.Symbol %X at %X\n", rel_type, os->offset + our_off - os->va + (curr - data));
       return;
    }
    curr += 8;
    DWORD block_size = *(PDWORD)curr;
    curr += sizeof(DWORD);
    PBYTE block = curr;
    curr += block_size;
    while( (block < curr) && (block < data_end) )
    {
      DWORD base_addr = *(PDWORD)block;
      PBYTE cblock = block;
      cblock += sizeof(DWORD);
      // read size
      DWORD bsize = *(PDWORD)cblock;
      cblock += sizeof(DWORD);
      block += bsize;
      printf("rel_type %X at %X bsize %X\n", rel_type, our_off + (block - data), bsize);
      if ( rel_type == 5 )
          for ( int idx = 0; (cblock < block) && (cblock < data_end); cblock += sizeof(IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION), idx++ )
          {
            PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION block5 = (PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION)cblock;
            // there are strange entries with zero at end of block. perhaps inserted just for alignment
            if ( !block5->PageRelativeOffset && idx )
              continue;
            printf(" addr %X, offset %X\n", block5->PageRelativeOffset + base_addr, our_off + (cblock - data));
          }
        else if ( rel_type == 4 )
          for ( int idx = 0; (cblock < block) && (cblock < data_end); cblock += sizeof(IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION), idx++ )
          {
            PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION block4 = (PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION)cblock;
            // there are strange entries with zero at end of block. perhaps inserted just for alignment
            if ( !block4->PageRelativeOffset && idx )
              continue;
            printf(" addr %X, offset %X\n", block4->PageRelativeOffset + base_addr, our_off + (cblock - data));
          }
        else if ( rel_type == 3 )
          for ( int idx = 0; (cblock < block) && (cblock < data_end); cblock += sizeof(IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION), idx++ )
          {
            PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION block3 = (PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION)cblock;
            printf(" addr %X, offset %X\n", block3->PageRelativeOffset + base_addr, our_off + (cblock - data));
          }
        else for ( int idx = 0; (cblock < block) && (cblock < data_end); cblock += sizeof(WORD), idx++ )
        {
            WORD off2 = *(PWORD)cblock;
            // there are strange entries with zero at end of block. perhaps inserted just for alignment
            if ( !off2 && idx )
              continue;
            printf(" addr %X, offset %X\n", off2 + base_addr, our_off + (cblock - data));
        }
    }
  }
}

int arm64_pe_file::map_pe(int verbose)
{
  if ( m_fp == NULL )
    return 0;
  if ( m_mz != NULL ) // already mapped ?
    return 0;
  // iterate over sections to find size of mapping and header
  DWORD max_size = 0;
  DWORD min_size = 0;
  for ( auto iter = m_sects.cbegin(); iter != m_sects.cend(); ++iter )
  {
    // for example PadXX sections has zero size
    if ( !iter->size )
      continue;
    if ( !min_size )
      min_size = iter->offset;
    else if ( min_size > iter->offset )
      min_size = iter->offset;
    DWORD aligned = align_size(iter->vsize);
    if ( iter->va + aligned > max_size )
      max_size = iter->va + aligned;
  }
  if ( verbose )
    printf("min_size %X, max_size %X\n", min_size, max_size);
  m_mz_size = max_size;
  // create "mapping"
  m_mz = (PBYTE)VirtualAlloc(NULL, m_mz_size, MEM_COMMIT, PAGE_READWRITE);
  if ( NULL == m_mz )
  {
    printf("VirtualAlloc(%X bytes) failed, error %d\n", m_mz_size, ::GetLastError());
    m_mz_size = 0;
    return 0;
  }
  // map each section
  for ( auto iter = m_sects.cbegin(); iter != m_sects.cend(); ++iter )
  {
    // for example PadXX sections has zero size
    if ( !iter->size )
      continue;
    fseek(m_fp, iter->offset, SEEK_SET);
    if ( 1 != fread(m_mz + iter->va, iter->size, 1, m_fp) )
    {
      printf("cannot copy section %s to %p\n", iter->name, m_mz + iter->va);
      VirtualFree(m_mz, 0, MEM_RELEASE);
      m_mz = NULL;
      m_mz_size = 0;
      return 0;
    }
    if ( verbose )
      printf("%s mapped %X to %p\n", iter->name, iter->size, m_mz + iter->va);
  }
  // hanging on the cake - MZ header
  fseek(m_fp, 0, SEEK_SET);
  fread(m_mz, min_size, 1, m_fp);
  return 1;
}
