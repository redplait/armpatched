#include "stdafx.h"
#include "fsd_reader.h"

int fsm_reader::open(const wchar_t *fname)
{
  // open file
  if ( m_fp != NULL )
  {
    fclose(m_fp);
    m_fp = NULL;
    m_line = 0;
  }
  errno_t err = _wfopen_s(&m_fp, fname, L"r");
  if ( err )
  {
    fprintf(stderr, "Cannot open file %S, error %d\n", fname, err);
    return 0;
  }
  return 1;
}

int fsm_reader::read_rule(found_xref **ref, path_edge &path)
{
  *ref = &m_symbol;
  while(1)
  {
    size_t size = 0;
    if ( curr == NULL )
    {
       if ( feof(m_fp) )
       {
         if ( m_state >= 2 )
         {
           path.last = item;
           m_state = 0;
           return 1;
         }
         return 0;
       }
       curr = read_string(size);
       if ( curr == NULL )
         return 0;
       trim_right(curr);
       curr = trim_left(curr);
       if (!*curr)
       {
         curr = NULL;
         continue;
       }
       if (is_comment(curr))
       {
         curr = NULL;
         continue;
       }
    }
    int res = parse(path);
    if ( res < 0 )
      return res;
    if ( res == 1 )
    {
       path.last = item;
       return 1;
    }
  }
  return 0;
}

#define NEXT    curr = NULL; return 0;
#define SLIST   if ( m_state == 3 ) { path.list.push_back(item); } m_state = 3;


int fsm_reader::parse(path_edge &path)
{
  DWORD stg_index = 0;
  // check for prefix stg - 3
  if ( !strncmp(curr, "stg", 3) )
  {
    curr = trim_left(curr + 3);
    char *end = NULL;
    stg_index = strtoul(curr, &end, 10);
    if ( !stg_index )
    {
      fprintf(stderr, "zero stg index at line %d\n", m_line);
      return -2;
    }
    curr = trim_left(end);
  }
  // section - 7
  if ( !strncmp(curr, "section", 7) )
  {
    if ( m_state > 1 )
    {
      m_state = 0;
      return 1;
    }
    m_state = 1;
    curr = trim_left(curr + 7);
    if ( !*curr )
    {
      fprintf(stderr, "bad section name at line %d\n", m_line);
      return -1;
    }
    path.symbol_section = curr;
    NEXT
  }
  // func - 4
  if ( !strncmp(curr, "func", 4) )
  {
    if ( m_state != 1 )
    {
      fprintf(stderr, "bad func at line %d, state %d\n", m_line, m_state);
      return -1;
    }
    m_state = 2; 
    curr = trim_left(curr + 4);
    if ( !*curr )
    {
      fprintf(stderr, "bad function name at line %d\n", m_line);
      return -1;
    }
    export_name = curr;
    m_symbol.section_name.clear();
    m_symbol.exported = export_name.c_str();
    m_symbol.stg_index = 0;
    NEXT
  }
  // sfunc - 5
  if ( !strncmp(curr, "sfunc", 5) )
  {
    if ( m_state != 1 )
    {
      fprintf(stderr, "bad sfunc at line %d, state %d\n", m_line, m_state);
      return -1;
    }
    m_state = 2; 
    curr = trim_left(curr + 5);
    if ( !*curr )
    {
      fprintf(stderr, "bad function storage at line %d\n", m_line);
      return -1;
    }
    char *end = NULL;
    m_symbol.stg_index = strtoul(curr, &end, 10);
    if ( !m_symbol.stg_index )
    {
      fprintf(stderr, "zero storage index for sfunc at line %d\n", m_line);
      return -2;
    }
    m_symbol.exported = NULL;
    m_symbol.section_name.clear();
    NEXT
  }
  // fsection - 8
  if ( !strncmp(curr, "fsection", 8) )
  {
    if ( m_state != 1 )
    {
      fprintf(stderr, "bad func at line %d, state %d\n", m_line, m_state);
      return -1;
    }
    m_state = 2; 
    curr = trim_left(curr + 8);
    if ( !*curr )
    {
      fprintf(stderr, "bad fsection name at line %d\n", m_line);
      return -1;
    }
    m_symbol.exported = NULL;
    m_symbol.section_name = curr;
    m_symbol.stg_index = 0;
    NEXT
  }
  // call_imp - 8
  if ( !strncmp(curr, "call_imp", 8) )
  {
    SLIST
    curr = trim_left(curr + 8);
    if ( !*curr )
    {
      fprintf(stderr, "bad call_imp name at line %d\n", m_line);
      return -1;
    }
    item.type = call_imp;
    item.name = curr;
    NEXT
  }
  // call_dimp - 9
  if ( !strncmp(curr, "call_dimp", 9) )
  {
    SLIST
    curr = trim_left(curr + 9);
    if ( !*curr )
    {
      fprintf(stderr, "bad call_dimp name at line %d\n", m_line);
      return -1;
    }
    item.type = call_imp;
    item.name = curr;
    NEXT
  }
  // call_imp - 8
  if ( !strncmp(curr, "call_exp", 8) )
  {
    SLIST
    curr = trim_left(curr + 8);
    if ( !*curr )
    {
      fprintf(stderr, "bad call_exp name at line %d\n", m_line);
      return -1;
    }
    item.type = call_exp;
    item.name = curr;
    NEXT
  }
  // call - 4
  // must be below all call_XXX for obvious reason
  if ( !strncmp(curr, "call", 4) )
  {
    SLIST
    item.type = call;
    item.name.clear();
    curr = trim_left(curr + 4);
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // load_cookie - 11
  if ( !strncmp(curr, "load_cookie", 11) )
  {
    SLIST
    item.type = ldr_cookie;
    NEXT
  }
  // gcall - 5
  if ( !strncmp(curr, "gcall", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gcall;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gcall at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // load - 4
  if ( !strncmp(curr, "load", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    item.type = load;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gload - 5
  if ( !strncmp(curr, "gload", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gload;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gload at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // ldrb - 4
  if ( !strncmp(curr, "ldrb", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    item.type = ldrb;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gldrb - 5
  if ( !strncmp(curr, "gldrb", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gldrb;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gldrb at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // ldrh - 4
  if ( !strncmp(curr, "ldrh", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    item.type = ldrh;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gldrh - 5
  if ( !strncmp(curr, "gldrh", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gldrh;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gldrh at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // store - 5
  if ( !strncmp(curr, "store", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = store;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gstore - 6
  if ( !strncmp(curr, "gstore", 6) )
  {
    SLIST
    curr = trim_left(curr + 6);
    item.type = gstore;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gstore at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // strb - 4
  if ( !strncmp(curr, "strb", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    item.type = strb;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gstrb - 5
  if ( !strncmp(curr, "gstrb", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gstrb;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gstrb at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // strh - 4
  if ( !strncmp(curr, "strh", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    item.type = strh;
    item.name.clear();
    if ( *curr )
      item.name = curr;
    item.stg_index = stg_index;
    NEXT
  }
  // gstrh - 5
  if ( !strncmp(curr, "gstrh", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    item.type = gstrh;
    char *end = NULL;
    item.stg_index = strtoul(curr, &end, 10);
    if ( !item.stg_index )
    {
      fprintf(stderr, "zero stg in gstrh at line %d\n", m_line);
      return -2;
    }
    NEXT
  }
  // const - 5
  if ( !strncmp(curr, "const", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    if ( !*curr )
    {
      fprintf(stderr, "bad const at line %d\n", m_line);
      return -1;
    }
    item.type = ldr_off;
    item.value_count = 0;
    char *end = NULL;
    item.value = strtoul(curr, &end, 16);
    NEXT
  }
  // rdata - 5
  if ( !strncmp(curr, "rdata", 5) )
  {
    SLIST
    curr = trim_left(curr + 5);
    if ( !*curr )
    {
      fprintf(stderr, "bad rdata at line %d\n", m_line);
      return -1;
    }
    item.type = ldr_rdata;
    size_t i;
    for ( i = 0; i < _countof(item.rconst); i++ )
      item.rconst[i] = 0;
    char *end = NULL;
    for ( i = 0; i < _countof(item.rconst); i++ )
    {
      item.rconst[i] = (BYTE)strtol(curr, &end, 16);
      if ( !*end )
        break;
      curr = trim_left(end);
    }
    NEXT
  }
  // guid - 4
  if ( !strncmp(curr, "guid", 4) )
  {
    SLIST
    curr = trim_left(curr + 4);
    if ( !*curr )
    {
      fprintf(stderr, "bad guid at line %d\n", m_line);
      return -1;
    }
    item.type = ldr_guid;
    size_t i;
    for ( i = 0; i < _countof(item.guid); i++ )
      item.guid[i] = 0;
    char *end = NULL;
    for ( i = 0; i < _countof(item.guid); i++ )
    {
      item.guid[i] = (BYTE)strtol(curr, &end, 16);
      if ( !*end )
        break;
      curr = trim_left(end);
    }
    NEXT
  }
  // ldrx - 4
  if ( !strncmp(curr, "ldrx", 4) )
  {
    SLIST
    item.type = ldrx;
    item.name.clear();
    item.stg_index = stg_index;
    item.reg_index = -1;
    curr = trim_left(curr + 4);
    if ( *curr )
      item.reg_index = atoi(curr);
    NEXT
  }
  // addx - 4
  if ( !strncmp(curr, "addx", 4) )
  {
    SLIST
    item.type = addx;
    item.name.clear();
    item.stg_index = stg_index;
    item.reg_index = -1;
    curr = trim_left(curr + 4);
    if ( *curr )
      item.reg_index = atoi(curr);
    NEXT
  }
  // movx - 4
  if ( !strncmp(curr, "movx", 4) )
  {
    SLIST
    item.type = movx;
    item.name.clear();
    item.stg_index = stg_index;
    item.reg_index = -1;
    curr = trim_left(curr + 4);
    if ( *curr )
      item.reg_index = atoi(curr);
    NEXT
  }
  fprintf(stderr, "cannot parse %s at line %d\n", curr, m_line);
  return -2;
}