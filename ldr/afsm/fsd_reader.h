#pragma once

#include "../deriv.h"
#include "base_reader.h"

class fsm_reader: public fsm_base_reader
{
  public:
    fsm_reader():
      fsm_base_reader()
    {
      m_state = 0;
      curr = NULL;
    }
    int open(const wchar_t *);
    int read_rule(found_xref **, path_edge &);
  protected:
    // returns negative result in case of parsing error
    // returns 1 if this is start of some new rule
    int parse(path_edge &);
    // states:
    // 0 - waiting for section
    // 1 - waiting for func/fsection
    // 2 - parse first item of rule
    // 3 - store item in path_edge, parse next item of rule
    int m_state;
    char *curr;
    found_xref m_symbol;
    path_item item;
    std::string export_name; // for found_xref.exported
};