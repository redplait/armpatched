#include "stdafx.h"
#include "base_reader.h"

fsm_base_reader::fsm_base_reader()
 : m_fp(NULL),
   m_line(0)
{
  m_ptr = NULL;
  m_alloced = 0;
}

fsm_base_reader::~fsm_base_reader()
{
  if ( m_ptr != NULL )
  {
    free(m_ptr);
    m_ptr = NULL;
  }
  if ( m_fp != NULL )
  {
    fclose(m_fp);
    m_fp = NULL;
  }
}

char *fsm_base_reader::read_string(size_t &size)
{
  if ( NULL == m_ptr )
  {
    m_alloced = 128;
    m_ptr = (char *)malloc(m_alloced);
    if ( m_ptr == NULL )
     return NULL;
  }
  char c;
  size = 0;
  while( !feof(m_fp) )
  {
    c = fgetc(m_fp);
    if ( feof(m_fp) )
     break;
    if ( !c )
     break;
    if ( c == 0xa )
     break;
    if ( c == 0xd )
    {
      if ( feof(m_fp) )
       break;
      c = fgetc(m_fp);
      if ( c == 0xa )
       break;
      else
       ungetc(c, m_fp);
    }
    /* add this symbol */
    if ( size >= m_alloced )
    {
      char *tmp = (char *)realloc(m_ptr, m_alloced *= 2);
      if ( tmp == NULL )
        return NULL;
      m_ptr = tmp;
    }
    m_ptr[size++] = c;
  }
  /* we need to add last zero symbol */
  if ( size >= m_alloced )
  {
     char *tmp = (char *)realloc(m_ptr, m_alloced + 1);
     if ( tmp == NULL )
       return NULL;
     m_ptr = tmp;
  }
  m_ptr[size] = 0;
  m_line++;
  return m_ptr;  
}

char *fsm_base_reader::next_token(char *str)
{
  while(*str)
  {
    if ( isspace(*str) )
      return str;
    str++;
  }
  return str;
}

char *fsm_base_reader::trim_left(char *str)
{
  while(*str)
  {
    if ( !isspace(*str) )
      return str;
    str++;
  }
  return str;
}

void fsm_base_reader::trim_right(char *str)
{
  char *ptr;
  for ( ptr = str; *ptr; ptr++ )
   ;
  for ( ptr--; ptr > str; ptr-- )
    if ( isspace(*ptr) )
      *ptr = 0;
    else
      return;
}

int fsm_base_reader::is_comment(char *str)
{
  return ( *str == '#' );
}
