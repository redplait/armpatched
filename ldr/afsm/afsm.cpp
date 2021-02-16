// afsm.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "stdafx.h"
#include "../deriv.h"
#include "fsd_reader.h"

int gSE = 1;
int gUseLC = 0;
int gUseRData = 1;

deriv_tests gTestPool;

void dump_edge(const path_edge &edges)
{
  for ( const auto &edge: edges.list )
    edge.dump();
}

void usage(const wchar_t *progname)
{
  printf("%S: [options] arm64_pe file(s)\n", progname);
  printf("Options:\n");
  printf(" -a filename.fsm\n");
  printf(" -v - verbose output\n");
  exit(6);
}

int wmain(int argc, wchar_t **argv)
{
  int verbose = 0;
  const wchar_t *fsm_name = NULL;
  
   if ( argc < 2 )
     usage(argv[0]);
   for ( int i = 1; i < argc; i++ )
   {
     if ( !wcscmp(argv[i], L"-v") )
     {
       verbose = 1;
       continue;
     }
     // -a
     if ( !wcscmp(argv[i], L"-a") )
     {
       if (fsm_name != NULL)
       {
         printf("You can apply only on FSM file\n");
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
   // read FSM rules and try to apply
   fsm_reader rdr;
   if ( !rdr.open(fsm_name) )
     return 1;
   while ( 1 )
   {
      found_xref *ref = NULL;
      path_edge path;
      int read_res = rdr.read_rule(&ref, path);
      if ( read_res <= 0 )
        break;
      if ( verbose )
        dump_edge(path);
      int mod_idx = 0;
      int has_stg = path.has_stg();
      for ( const auto &mod: gTestPool.mods )
      {
        mod.der->prepare(*ref, path);
        DWORD found = 0;
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
