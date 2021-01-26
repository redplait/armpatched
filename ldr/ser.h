#pragma once

#include "deriv.h"

class serialize
{
  public:
    serialize(const wchar_t *name)
     : fname(name)
    {
      m_fp = NULL;
    }
    virtual ~serialize()
    {
      if ( m_fp != NULL )
      {
        fclose(m_fp);
        m_fp = NULL;
      }
    }
    virtual int save(const found_xref &what, const path_edge &edges) = 0;
  protected:
    errno_t open()
    {
      if ( m_fp != NULL )
        fclose(m_fp);
       return _wfopen_s(&m_fp, fname.c_str(), L"a");
    }
    FILE *m_fp;
    std::wstring fname;
};

class pod_serialize: public serialize
{
  public:
    pod_serialize(const wchar_t *name)
      : serialize(name)
    { }
    virtual int save(const found_xref &what, const path_edge &edges);
};