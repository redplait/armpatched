#include "stdafx.h"
#include "pe_file.h"

void usage(const wchar_t *progname)
{
  printf("%S: [options] arm64_pe file(s)\n", progname);
  printf("Options:\n");
  printf(" -de - dump exports\n");
  printf(" -dr - dump relocs\n");
  printf(" -ds - dump sections\n");
  printf(" -d  - dump all\n");
  exit(6);
}

typedef int (arm64_pe_file::*TDirGet)(DWORD &, DWORD &) const;

int wmain(int argc, wchar_t **argv)
{
   int dump_exp = 0;
   int dump_sects = 0;
   int dump_relocs = 0;
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
     if ( !wcscmp(argv[i], L"-de") )
     {
       dump_exp = 1;
       continue;
     }
     if ( !wcscmp(argv[i], L"-dr") )
     {
       dump_relocs = 1;
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
     printf("%S:\n", argv[i]);
     arm64_pe_file f(argv[i]);
     if ( f.read(dump_sects) )
       continue;
     // dump PE directories
     printf("ImageBase: %p\n", f.image_base());
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
     // read exports
     exports_dict *ed = f.get_export_dict();
     if ( NULL != ed )
     {
       if ( dump_exp )
         ed->dump();
       delete ed;
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
   }
   return 0;
}
