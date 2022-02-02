// afsm.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "stdafx.h"
#include "../deriv.h"
#include "fsd_reader.h"
#include "yara.h"

int g_verbose = 0;
int gSE = 1;
int gCE = 0;
int gUseLC = 0;
int gUseRData = 1;

deriv_tests gTestPool;

struct yara_data
{
  YR_COMPILER *y_comp;
  YR_RULES *y_rules;
  std::wstring yara_file;

  yara_data()
   : y_comp(NULL),
     y_rules(NULL)
  { }

  void del_compiler()
  {
    if ( y_comp != NULL )
    {
      yr_compiler_destroy(y_comp);
      y_comp = NULL;
    }
  }
  void del_rules()
  {
    if ( y_rules != NULL )
    {
      yr_rules_destroy(y_rules);
      y_rules = NULL;
    }
  }

  ~yara_data()
  {
    del_compiler();
    del_rules();
  }
} g_yara_data;

static void print_compiler_error(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  const char* msg_type;

  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    msg_type = "error";
  }
  else
  {
    msg_type = "warning";
  }

  if (rule != NULL)
  {
    fprintf(
        stderr,
        "%s: rule \"%s\" in %s(%d): %s\n",
        msg_type,
        rule->identifier,
        file_name,
        line_number,
        message);
  }
  else
  {
    fprintf(
        stderr, "%s(%d): %s: %s\n", file_name, line_number, msg_type, message);
  }
}

struct scan_user_data
{
  std::map<std::string, std::set<DWORD> > *results;
  DWORD section_base;
};

int scan_cb(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  if ( message != CALLBACK_MSG_RULE_MATCHING )
    return CALLBACK_CONTINUE;
  YR_RULE *rule = (YR_RULE*)message_data;
  scan_user_data *sud = (scan_user_data *)user_data;
  printf("%s ", rule->identifier);
  std::set<DWORD> &curr_set = (*sud->results)[rule->identifier];
  YR_STRING* string;
  yr_rule_strings_foreach(rule, string)
  {
    YR_MATCH* match;
    yr_string_matches_foreach(context, string, match)
    {
      DWORD rva = sud->section_base + match->base + match->offset;
      if ( g_verbose )
        printf(" %X", rva);
      curr_set.insert(rva);
    }
  }
  printf("\n");

  return CALLBACK_CONTINUE;
}

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring &wstr)
{
    if( wstr.empty() ) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo( size_needed, 0 );
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void dump_edge(const path_edge &edges)
{
  if ( !edges.scan_list.empty() )
  {
    for ( const auto &scan: edges.scan_list )
      scan.dump_at();
  } else
  {
    for ( const auto &edge: edges.list )
      edge.dump();
  }
}

void usage(const wchar_t *progname)
{
  printf("%S: [options] arm64_pe file(s)\n", progname);
  printf("Options:\n");
  printf(" -a filename.fsm\n");
  printf(" -v - verbose output\n");
  printf(" -y - YARA rules file\n");
  exit(6);
}

int wmain(int argc, wchar_t **argv)
{
  const wchar_t *fsm_name = NULL;
  
   if ( argc < 2 )
     usage(argv[0]);
   for ( int i = 1; i < argc; i++ )
   {
     if ( !wcscmp(argv[i], L"-v") )
     {
       g_verbose = 1;
       continue;
     }
     // -y
     if ( !wcscmp(argv[i], L"-y") )
     {
       if ( !g_yara_data.yara_file.empty() )
       {
         printf("You can use only one YARA file\n");
         usage(argv[0]);
       }
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       g_yara_data.yara_file = argv[i];
       continue;        
     }
     // -a
     if ( !wcscmp(argv[i], L"-a") )
     {
       if (fsm_name != NULL)
       {
         printf("You can apply only one FSM file\n");
         usage(argv[0]);
       }
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       fsm_name = argv[i];
       continue;
     }
     // perhaps this is some file(s) to test on them
     if ( !gTestPool.add_module(argv[i]) )
       printf("Cannot read %S\n", argv[i]);
   }
   if ( gTestPool.empty() )
     usage(argv[0]);
   if ( NULL == fsm_name )
     usage(argv[0]);
   // check if we have yara file
   if ( !g_yara_data.yara_file.empty() )
   {
     int y_res = yr_initialize();
     if (y_res != ERROR_SUCCESS)
     {
       fprintf(stderr, "yr_initialize error (%d)\n", y_res);
       return y_res;
     }
     // alloc compiler
     y_res = yr_compiler_create(&g_yara_data.y_comp);
     if (y_res != ERROR_SUCCESS)
     {
       fprintf(stderr, "yr_compiler_create error (%d)\n", y_res);
       return y_res;
     }
     yr_compiler_set_callback(g_yara_data.y_comp, print_compiler_error, NULL);
     // open file and pass it to YARA compiler
     FILE *fp = NULL;
     _wfopen_s(&fp, g_yara_data.yara_file.c_str(), L"r");
     if ( NULL == fp )
     {
        fprintf(stderr, "cannot open yara file %S\n", g_yara_data.yara_file.c_str());
        return 1;
     }
     std::string utf8_name = utf8_encode(g_yara_data.yara_file.c_str());
     y_res = yr_compiler_add_file(g_yara_data.y_comp, fp, NULL, utf8_name.c_str());
     fclose(fp);
     if (y_res != ERROR_SUCCESS)
     {
       fprintf(stderr, "yr_compiler_add_file error (%d)\n", y_res);
       return y_res;
     }
     y_res = yr_compiler_get_rules(g_yara_data.y_comp, &g_yara_data.y_rules);
     if ( y_res != ERROR_SUCCESS)
     {
       fprintf(stderr, "yr_compiler_get_rules error (%d)\n", y_res);
       return y_res;
     }
     g_yara_data.del_compiler();
     // now apply yara rules to whole test set
     for ( auto &mod: gTestPool.mods )
     {
       std::list<one_section> slist;
       mod.pe->get_exec_sections(slist);
       scan_user_data sud { &mod.der->yara_results };
       for ( const auto &siter: slist )
       {
         sud.section_base = siter.va;
         y_res = yr_rules_scan_mem(g_yara_data.y_rules, mod.der->base_addr() + siter.va, siter.size, CALLBACK_MSG_RULE_MATCHING, scan_cb, &sud, 100);
         if ( y_res != ERROR_SUCCESS)
         {
           fprintf(stderr, "yr_rules_scan_mem on %S section %s error: %d\n", mod.fname.c_str(), siter.name, y_res);
         }
       }
     }
     g_yara_data.del_rules();
     yr_finalize();
   }
   // read FSM rules and try to apply
   fsm_reader rdr;
   if ( !rdr.open(fsm_name) )
     return 1;
   Rules_set rules_set;
   while ( 1 )
   {
      found_xref *ref = NULL;
      path_edge path;
      int read_res = rdr.read_rule(&ref, path);
      if ( read_res <= 0 )
        break;
      if ( g_verbose )
        dump_edge(path);
      if ( path.m_rule && !path.is_scan() )
      {
        rules_set[path.m_rule] = path;
        continue;
      }
      int mod_idx = 0;
      int has_stg = path.has_stg();
      for ( const auto &mod: gTestPool.mods )
      {
        mod.der->prepare(*ref, path);
        DWORD found = 0;
        if ( path.is_scan() )
        {
          if ( !validate_scan(rules_set, path) )
            continue;
          if ( mod.der->apply_scan(*ref, path, rules_set) )
          {
            printf("[%d] %S: scanned\n", mod_idx, mod.fname.c_str());
            auto stg = mod.der->get_stg();
            std::for_each(stg.cbegin(), stg.cend(), [](const auto &item) { printf(" %d - %X\n", item.first, item.second); });
          }
          continue;
        }
        if ( mod.der->apply(*ref, path, found) )
        {
          printf("[%d] %S: found at %X\n", mod_idx, mod.fname.c_str(), found);
          if ( has_stg )
          {
            auto stg = mod.der->get_stg();
            std::for_each(stg.cbegin(), stg.cend(), [](const auto &item) { printf(" %d - %X\n", item.first, item.second); });
          }
        }
        mod_idx++;
      }
   }
   return 0;
}
