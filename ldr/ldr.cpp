#include "stdafx.h"
#include "pe_file.h"
#include "afd_hack.h"
#include "skci_hack.h"
#include "krnl_hack.h"
#include "ndis_hack.h"
#include "combase_hack.h"
#include "ntdll_hack.h"
#include "rpc_hack.h"
#include "rpcrt4_hack.h"
#include "deriv.h"
#include "../source/armadillo.h"

// some global options
int gSE = 0;

void usage(const wchar_t *progname)
{
  printf("%S: [options] arm64_pe file(s)\n", progname);
  printf("Options:\n");
  printf(" -dlc - dump load_config\n");
  printf(" -de - dump exports\n");
  printf(" -di - dump imports\n");
  printf(" -dr - dump relocs\n");
  printf(" -ds - dump sections\n");
  printf(" -d  - dump all\n");
  printf(" -rpc - find rpc interfaces\n");
  printf(" -se - skip exported branches\n");
  printf(" -t threads number\n");
  printf(" -T test file\n");
  printf(" -v - verbose output\n");
  printf(" -wpp - try to find WPP_GLOBAL_Controls\n");
  exit(6);
}

void dump_import(module_import *mi)
{
   printf("IAT rva %X size %X count %X\n", mi->iat_rva, mi->iat_size, mi->iat_count);
   if ( mi->iat_count )
     for ( DWORD i = 0; i < mi->iat_count; i++ )
     {
       if ( mi->iat[i].name != NULL )
         printf("%X %s.%s\n", i, mi->iat[i].modname, mi->iat[i].name);
       else
         printf("%X %s.%d\n", i, mi->iat[i].modname, mi->iat[i].ordinal);
     }
}

typedef int (arm64_pe_file::*TDirGet)(DWORD &, DWORD &) const;

template <typename T>
void hack_dump(arm64_pe_file *f, exports_dict *ed, int verb_mode)
{
  T usermod(f, ed);
  usermod.hack(verb_mode);
  usermod.dump();
}

template <typename T>
void process_iat_mod(arm64_pe_file *f, exports_dict *ed, module_import *iat, int verb_mode)
{
  T usermod(f, ed, iat);
  usermod.hack(verb_mode);
  usermod.dump();
}

template <typename T>
void process_wpp(arm64_pe_file *f, exports_dict *ed, module_import *iat, int verb_mode)
{
  T usermod(f, ed, iat);
  std::set<PBYTE> res;
  usermod.hack_wpp(res, verb_mode);
  if ( !res.empty() )
  {
    printf("WPP_GLOBAL_Controls:\n");
    PBYTE mz = f->base_addr();
    for ( auto citer = res.cbegin(); citer != res.cend(); ++citer )
      printf(" %p\n", PVOID(*citer - mz));
  }
}

std::list<std::wstring> gTests;

typedef std::pair<std::wstring, DWORD> Der;

int derive_edges(DWORD rva, PBYTE mz, deriv_hack *der, std::list<found_xref> &xrefs)
{
  int can_be_found = 0;
  deriv_tests tests;
  if ( !gTests.empty() )
  {
    for ( const auto &c: gTests )
      tests.add_module(c.c_str());
  }
  for ( auto &x: xrefs )
  {
     if ( x.exported != NULL )
        printf("found at %p - %s\n", PVOID(x.pfunc - mz), x.exported);
     else
     {
        if ( x.section_name.empty() )
          printf("found at %p\n", PVOID(x.pfunc - mz));
        else
          printf("found at %p in section %s\n", PVOID(x.pfunc - mz), x.section_name.c_str());
     }
     // try autobuild path edges
     path_edge edges;
     if ( der->make_path(rva, x.pfunc, edges) )
     {
        for ( auto edge: edges.list )
          edge.dump();
        edges.last.dump();
        if ( x.exported != NULL )
        {
          if (edges.reduce())
          {
            printf("REDUCED:\n");
            // dump again
            for (auto edge : edges.list)
              edge.dump();
            edges.last.dump();
          }
          if ( tests.mods.empty() )
          {
            DWORD rva_found = 0;
            if ( der->apply(x, edges, rva_found) )
            {
              printf("apply return %X, must_be %X\n", rva_found, rva);
              if ( rva == rva_found )
                can_be_found++;
            }
          } else {
            DWORD idx = 0;
            for ( auto miter = tests.mods.begin(); miter != tests.mods.end(); miter++, idx++ )
            {
              DWORD rva_found = 0;
              if ( miter->der->apply(x, edges, rva_found) )
                printf("Test[%d]: %X\n", idx, rva_found);
            }
          }
        } else {
          if ( edges.is_trivial() )
             printf("TRIVIAL\n");
          else if ( edges.has_const_count(3) )
          {
            if (edges.reduce())
            {
              printf("REDUCED:\n");
              // dump again
              for (auto edge : edges.list)
                edge.dump();
              edges.last.dump();
            }
            if ( tests.mods.empty() )
            {
              DWORD rva_found = 0;
              if (der->apply(x, edges, rva_found))
              {
                printf("apply return %X, must_be %X\n", rva_found, rva);
                if (rva == rva_found)
                  can_be_found++;
              }
            } else {
              DWORD idx = 0;
              for ( auto miter = tests.mods.begin(); miter != tests.mods.end(); miter++, idx++ )
              {
                DWORD rva_found = 0;
                if ( miter->der->apply(x, edges, rva_found) )
                  printf("Test[%d]: %X\n", idx, rva_found);
              }
            }
          }
        }
     }
  }
  if ( can_be_found )
    printf("CANBEFOUND\n");
  return can_be_found;
}

int wmain(int argc, wchar_t **argv)
{
   int dump_exp = 0;
   int dump_imp = 0;
   int dump_sects = 0;
   int dump_relocs = 0;
   int dump_lc = 0;
   int verb_mode = 0;
   int rpc_mode = 0;
   int find_wpp = 0;
   int threads_count = 0;
   std::list<Der> derives;
   std::pair<TDirGet, const char *> dir_get[] = { 
     std::make_pair(&arm64_pe_file::get_export, "export"),
     std::make_pair(&arm64_pe_file::get_import, "import"),
     std::make_pair(&arm64_pe_file::get_delayed_import, "delayed_import"),
     std::make_pair(&arm64_pe_file::get_bound_import, "get_bound"),
     std::make_pair(&arm64_pe_file::get_rsrc, "resources"),
     std::make_pair(&arm64_pe_file::get_security, "security"),
     std::make_pair(&arm64_pe_file::get_rel, "relocs"),
     std::make_pair(&arm64_pe_file::get_arch, "arch"),
     std::make_pair(&arm64_pe_file::get_gp, "GLOBALPTR"),
     std::make_pair(&arm64_pe_file::get_tls, "TLS"),
     std::make_pair(&arm64_pe_file::get_iat, "IAT"),
     std::make_pair(&arm64_pe_file::get_load_config, "load_config"),
     std::make_pair(&arm64_pe_file::get_exceptions, "exceptions"),
     std::make_pair(&arm64_pe_file::get_net, "COM")
   };
   if ( argc < 2 )
     usage(argv[0]);
   for ( int i = 1; i < argc; i++ )
   {
     if ( !wcscmp(argv[i], L"-T") )
     {
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       gTests.push_back(argv[i]);
       continue;
     }
     if ( !wcscmp(argv[i], L"-t") )
     {
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       threads_count = _wtoi(argv[i]);
       if ( threads_count )
       {
         int proc_count = std::thread::hardware_concurrency();
         if ( proc_count < threads_count )
           threads_count = proc_count;
       }
       continue;
     }
     if ( !wcscmp(argv[i], L"-der") )
     {
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       Der d;
       d.first = argv[i];
       i++;
       if ( i >= argc )
       {
         usage(argv[0]);
         return 0;
       }
       wchar_t *end;
       d.second = wcstol(argv[i], &end, 16);
       derives.push_back(d);
       continue;
     }
     if ( !wcscmp(argv[i], L"-se") )
     {
       gSE = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-de") )
     {
       dump_exp = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-di") )
     {
       dump_imp = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-dr") )
     {
       dump_relocs = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-dlc") )
     {
       dump_lc = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-ds") )
     {
       dump_sects = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-d") )
     {
       dump_exp = 1;
       dump_relocs = 1;
       dump_sects = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-v") )
     {
       verb_mode = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-rpc") )
     {
       rpc_mode = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-wpp") )
     {
       find_wpp = 1;
       continue;
     }
     printf("%S:\n", argv[i]);
     arm64_pe_file f(argv[i]);
     if ( f.read(dump_sects) )
       continue;
     // dump PE directories
     printf("ImageBase: %I64X\n", f.image_base());
     if ( verb_mode )
     {
       for ( const auto &diter : dir_get )
       {
         DWORD addr = 0;
         DWORD size = 0;
         if ( ! (f.*(diter.first))(addr, size) )
           continue;
         printf("%s dir: rva %X size %X\n", diter.second, addr, size);
         const one_section *where = f.find_section_rva(addr);
         if ( NULL == where )
           continue;
         if (where->offset)
           printf(" in section %s, file offset %X\n", where->name, where->offset + addr - where->va);
         else
           printf(" in section %s\n", where->name);
       }
     }
     // read exports
     exports_dict *ed = f.get_export_dict();
     if ( NULL != ed )
     {
       if ( dump_exp )
         ed->dump();
     }
     // dump relocs
     if ( dump_relocs )
     {
       DWORD r_size = 0;
       PBYTE rbody = f.read_relocs(r_size);
       if ( rbody != NULL )
       {
         PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)rbody;
         PBYTE  RelEnd = ((PBYTE)BaseReloc + r_size);
         while ((PBYTE)BaseReloc < RelEnd && BaseReloc->SizeOfBlock)
         {
           PRELOC Reloc = (PRELOC)((PBYTE)BaseReloc + sizeof(IMAGE_BASE_RELOCATION));
           for (DWORD i = 0;
                (i < (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC)) &&
                ((PBYTE)&Reloc[i] < RelEnd);
                i++
               )
           {
             if ( !Reloc[i].Type ) // I don`t know WTF is absolute reloc means
               continue;
             const one_section *where = f.find_section_rva(BaseReloc->VirtualAddress + Reloc[i].Offset);
             if ( where == NULL )
               printf("reltype %d offset %X\n", Reloc[i].Type, BaseReloc->VirtualAddress + Reloc[i].Offset);
             else
               printf("reltype %d offset %X %s\n", Reloc[i].Type, BaseReloc->VirtualAddress + Reloc[i].Offset, where->name);
           }
           BaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseReloc + BaseReloc->SizeOfBlock);
         }
       }
       free(rbody);
     }
     // dump load_config
     if ( dump_lc )
     {
       DWORD lc_size = 0;
       Prfg_IMAGE_LOAD_CONFIG_DIRECTORY64 lc = (Prfg_IMAGE_LOAD_CONFIG_DIRECTORY64)f.read_load_config(lc_size);
       if ( lc != NULL && lc_size )
       {
         printf("load_config size: %X\n", lc_size);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerTable) && lc->SecurityCookie )
           printf("SecurityCookie: %I64X\n", lc->SecurityCookie);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer) && lc->GuardCFCheckFunctionPointer )
           printf("GuardCFCheckFunctionPointer: %I64X\n", lc->GuardCFCheckFunctionPointer);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable) && lc->GuardCFDispatchFunctionPointer )
           printf("GuardCFDispatchFunctionPointer: %I64X\n", lc->GuardCFDispatchFunctionPointer);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardRFFailureRoutineFunctionPointer) && lc->GuardRFFailureRoutine )
           printf("GuardRFFailureRoutine: %I64X\n", lc->GuardRFFailureRoutine);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset) && lc->GuardRFFailureRoutineFunctionPointer )
           printf("GuardRFFailureRoutineFunctionPointer: %I64X\n", lc->GuardRFFailureRoutineFunctionPointer);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, HotPatchTableOffset) && lc->GuardRFVerifyStackPointerFunctionPointer )
           printf("GuardRFVerifyStackPointerFunctionPointer: %I64X\n", lc->GuardRFVerifyStackPointerFunctionPointer);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer) && lc->DynamicValueRelocTable )
           printf("DynamicValueRelocTable: %I64X\n", lc->DynamicValueRelocTable);
         int has_rfg = 0;
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection) && lc->DynamicValueRelocTableOffset )
         {
           printf("DynamicValueRelocTableOffset: %X\n", lc->DynamicValueRelocTableOffset);
           has_rfg = 1;
         }
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, Reserved2) )
           printf("DynamicValueRelocTableSection: %X\n", lc->DynamicValueRelocTableSection);
         // dump RFG relocs
         if ( has_rfg )
           f.dump_rfg_relocs();
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, VolatileMetadataPointer) && lc->VolatileMetadataPointer )
           printf("VolatileMetadataPointer: %I64X\n", lc->VolatileMetadataPointer);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationTable) && lc->GuardEHContinuationTable )
           printf("GuardEHContinuationTable: %I64X\n", lc->GuardEHContinuationTable);
         if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount) && lc->GuardEHContinuationCount )
           printf("GuardEHContinuationCount: %I64X\n", lc->GuardEHContinuationCount);
         // dump XFG
         if ( lc_size >= 0x130 )
         {
           UINT64 val = *(UINT64 *)((PBYTE)lc + 0x118);
           if ( val != NULL )
             printf("GuardXFGCheckFunctionPointer: %I64X\n", val);
           val = *(UINT64 *)((PBYTE)lc + 0x120);
           if ( val != NULL )
             printf("GuardXFGDispatchFunctionPointer: %I64X\n", val);
           val = *(UINT64 *)((PBYTE)lc + 0x128);
           if ( val != NULL )
             printf("GuardXFGTableDispatchFunctionPointer: %I64X\n", val);
         }
       }
     }
     if ( f.map_pe(verb_mode) )
     {
       inmem_import_holder ih;
       module_import *mimp = ih.add(argv[i], &f);
       // check if we need to dump imports
       if ( dump_imp )
       {
         if ( mimp != NULL )
           dump_import(mimp);
       }
       // apply relocs
       f.apply_relocs();
       if ( ed != NULL )
       {
         // quick and dirty test based on module name from exports
         const char *exp_name = f.get_exp_name();
         int krnl = 1;
         if ( find_wpp )
         {
           krnl = 0;
           process_wpp<iat_mod>(&f, ed, mimp, verb_mode);
           ed = NULL; // will be killed inside ~arm64_hack
         } else if ( rpc_mode )
         {
           krnl = 0;
           rpc_hack mod(&f, ed, mimp);
           ed = NULL; // will be killed inside ~arm64_hack
           mod.hack(verb_mode);
           mod.dump();
         } else if ( exp_name != NULL )
         {
           printf("%s\n", exp_name);
           if ( !_stricmp(exp_name, "ndis.sys") )
           {
             krnl = 0;
             if ( mimp != NULL )
             {
               ndis_hack ndis(&f, ed, mimp);
               ed = NULL; // will be killed inside ~arm64_hack
               ndis.hack(verb_mode);
               ndis.dump();
             }
           } else if ( !_stricmp(exp_name, "skci.dll") )
           {
             krnl = 0;
             if ( mimp != NULL )
             {
               skci_hack skci(&f, ed, mimp);
               ed = NULL; // will be killed inside ~arm64_hack
               skci.hack(verb_mode);
               skci.dump();
             }
           } else if ( !_stricmp(exp_name, "ntdll.dll") )
           {
             krnl = 0;
             hack_dump<ntdll_hack>(&f, ed, verb_mode);
             ed = NULL; // will be killed inside ~arm64_hack
           } else if ( !_stricmp(exp_name, "rpcrt4.dll") )
           {
             krnl = 0;
             hack_dump<rpcrt4_hack>(&f, ed, verb_mode);
             ed = NULL; // will be killed inside ~arm64_hack
           } else if ( !_stricmp(exp_name, "combase.dll") )
           {
             krnl = 0;
             process_iat_mod<combase_hack>(&f, ed, mimp, verb_mode);
             ed = NULL; // will be killed inside ~arm64_hack
           }
         }
         if ( krnl )
         {
           ntoskrnl_hack nt(&f, ed);
           ed = NULL; // will be killed inside ~arm64_hack
           nt.hack(verb_mode);
           nt.dump();
         }
       } else {
          // try to get module name from file name
          wchar_t *wname = ::PathFindFileNameW(argv[i]);
          if ( wname != NULL )
          {
            printf("mod name: %S\n", wname);
            if ( !_wcsicmp(wname, L"afd.sys") )
            {
              afd_hack afd(&f, ed, mimp);
              afd.hack(verb_mode);
              afd.dump();
            }
          }
       }
     }
     if ( ed != NULL )
       delete ed;
   }
   for ( auto c: derives )
   {
     arm64_pe_file f(c.first.c_str());
     if ( f.read(dump_sects) )
       continue;
     exports_dict *ed = f.get_export_dict();
     if ( f.map_pe(verb_mode) )
     {
       inmem_import_holder ih;
       module_import *mimp = ih.add(c.first.c_str(), &f);
       std::list<found_xref> xrefs;
       if ( threads_count )
       {
         deriv_pool der_pool(&f, ed, mimp, threads_count);
         if ( der_pool.find_xrefs(c.second, xrefs) )
           derive_edges(c.second, f.base_addr(), der_pool.get_first(), xrefs);
       } else {
         deriv_hack der(&f, ed, mimp);
         if ( der.find_xrefs(c.second, xrefs) )
           derive_edges(c.second, f.base_addr(), &der, xrefs);
       }
     }
   }
   return 0;
}
