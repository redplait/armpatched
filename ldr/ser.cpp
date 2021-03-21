#include "stdafx.h"
#include "ser.h"

int pod_serialize::save(const found_xref &what, const path_edge &edges)
{
  // open file
  errno_t err = open();
  if ( err )
  {
    fprintf(stderr, "Cannot open file %S, error %d\n", fname.c_str(), err);
    return 0;
  }
  fprintf(m_fp, "section %s\n", edges.symbol_section.c_str());
  if ( what.is_exported() )
  {
    if ( what.exported != NULL )
      fprintf(m_fp, "func %s\n", what.exported);
    else
      fprintf(m_fp, "func ord%d\n", what.exported_ord);
  } else if ( !what.yara_rule.empty() )
   fprintf(m_fp, "yfunc %s\n", what.yara_rule.c_str()); 
  else
    fprintf(m_fp, "fsection %s\n", what.section_name.c_str());
  // store edges
  std::for_each(edges.list.begin(), edges.list.end(), [&](const path_item &item) { item.pod_dump(m_fp); });
  fprintf(m_fp, "\n");
  return 1;
}