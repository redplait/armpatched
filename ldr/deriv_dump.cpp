#include "stdafx.h"
#include "deriv.h"

void path_item::pod_dump(FILE *fp) const
{
  if ( rva )
    fprintf(fp, " # rva %X\n", rva);
  switch(type)
  {
    case ldr_cookie:
        fprintf(fp, " load_cookie\n");
      break;

    case gcall:
       fprintf(fp, " gcall %d\n", stg_index);
      break;
    case call:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " call\n");
       else
         fprintf(fp, " call %s\n", name.c_str());
      break;

    case sload:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       fprintf(fp, " sload %s\n", name.c_str());
      break;
    case load:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " load\n");
       else
         fprintf(fp, " load %s\n", name.c_str());
      break;
    case gload:
       fprintf(fp, " gload %d\n", stg_index);
      break;

    case sstore:
       if ( stg_index )
          fprintf(fp, " stg%d", stg_index);
        fprintf(fp, " sstore %s\n", name.c_str());
       break;
    case store: 
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " store\n");
       else
         fprintf(fp, " store %s\n", name.c_str());
       break;
    case gstore:
         fprintf(fp, " gstore %d\n", stg_index);
       break;

    case sldrb:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
        fprintf(fp, " sldrb %s\n", name.c_str());
       break;
    case ldrb:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " ldrb\n");
       else
         fprintf(fp, " ldrb %s\n", name.c_str());
       break;
    case gldrb:
         fprintf(fp, " gldrb %d\n", stg_index);
       break;

    case sldrh:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
        fprintf(fp, " sldrh %s\n", name.c_str());
       break;
    case ldrh:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " ldrh\n");
       else
         fprintf(fp, " ldrh %s\n", name.c_str());
       break;
    case gldrh:
         fprintf(fp, " gldrh %d\n", stg_index);
       break;

    case sstrb:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
        fprintf(fp, " sstrb %s\n", name.c_str());
       break;
    case strb:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " strb\n");
       else
         fprintf(fp, " strb %s\n", name.c_str());
       break;
    case gstrb:
         fprintf(fp, " gstrb %d\n", stg_index);
       break;

    case sstrh:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
        fprintf(fp," sstrh %s\n", name.c_str());
       break;
    case strh:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( name.empty() )
         fprintf(fp, " strh\n");
       else
         fprintf(fp," strh %s\n", name.c_str());
       break;
    case gstrh:
         fprintf(fp, " gstrh %d\n", stg_index);
       break;

    case ldr_guid:
         fprintf(fp, " guid");
         for ( size_t i = 0; i < _countof(guid); i++ )
           fprintf(fp, " %2.2X", guid[i]);
          fprintf(fp, "\n");
       break;
    case ldr_rdata:
         fprintf(fp, " rdata");
         for ( size_t i = 0; i < _countof(rconst); i++ )
           fprintf(fp, " %2.2X", rconst[i]);
          fprintf(fp, "\n");
       break;
    case ldr_off:
         fprintf(fp, " const %X\n", value);
       break;
    case ldr64_off:
         fprintf(fp, " const %I64X\n", value64);
       break;
    case limp:
         fprintf(fp, " limp %s\n", name.c_str());
       break;
    case call_imp:
        fprintf(fp, " call_imp %s\n", name.c_str());
       break;
    case call_dimp:
        fprintf(fp, " call_dimp %s\n", name.c_str());
       break;
    case call_exp:
        fprintf(fp, " call_exp %s\n", name.c_str());
       break;
    case call_icall:
        fprintf(fp, " call_icall\n");
       break;
    case ldrx:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( -1 == reg_index )
         fprintf(fp, " ldrx\n");
       else
         fprintf(fp, " ldrx %d\n", reg_index);
       break;
    case strx:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( -1 == reg_index )
         fprintf(fp, " strx\n");
       else
         fprintf(fp, " strx %d\n", reg_index);
       break;
    case addx:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( -1 == reg_index )
         fprintf(fp, " addx\n");
       else
         fprintf(fp, " addx %d\n", reg_index);
       break;
    case movx:
       if ( stg_index )
         fprintf(fp, " stg%d", stg_index);
       if ( -1 == reg_index )
         fprintf(fp, " movx\n");
       else
         fprintf(fp, " movx %d\n", reg_index);
       break;  
    case rule:
        fprintf(fp, " at %d rule %d\n", at, reg_index);
       break;
    default:
        fprintf(fp, " unknown type %d\n", type);
  }  
}

void path_item::dump_at() const
{
  printf(" at %d", at);
  switch(type)
  {
    case ldr_off:
         printf(" const %X\n", value);
       break;
    case ldr64_off:
         printf(" const %I64X\n", value64);
       break;
    case sload:
         printf(" sload %s\n", name.c_str());
       break; 
    case gload:
        printf(" gload %d\n", stg_index);
       break;
    case gcall:
        printf(" gcall %d\n", stg_index);
       break;
    case call_imp:
        printf(" call_imp %s\n", name.c_str());
       break;
    case call_dimp:
        printf(" call_dimp %s\n", name.c_str());
       break;
    case call_exp:
        printf(" call_exp %s\n", name.c_str());
       break;
    case ldr_guid:
         printf(" guid");
         for ( size_t i = 0; i < _countof(guid); i++ )
           printf(" %2.2X", guid[i]);
         if ( value_count )
           printf(" count %d\n", value_count);
         else
           printf("\n");
       break;
    case rule:
        printf(" rule %d\n", reg_index);
       break;
    default:
        printf(" unknown type %d\n", type);
  }
}

void path_item::dump() const
{
  printf(" RVA %X", rva);
  if ( wait_for )
    printf(" wait");
  switch(type)
  {
    case ldr_cookie:
        printf(" load_cookie\n");
      break;
    case gcall:
        printf(" gcall %d\n", stg_index);
      break;
    case call:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" call\n");
       else
         printf(" call in %s section\n", name.c_str());
      break;

    case sload:
       if ( stg_index )
         printf(" stg%d", stg_index);
       printf(" sload %s\n", name.c_str());
      break;
    case load:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" load\n");
       else
         printf(" load exported %s\n", name.c_str());
      break;
    case gload: 
        printf(" gload %d\n", stg_index);
      break;

    case sstore: 
       if ( stg_index )
         printf(" stg%d", stg_index);
        printf(" sstore %s\n", name.c_str());
       break;
    case store: 
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" store\n");
       else
         printf(" store exported %s\n", name.c_str());
       break;
    case gstore: 
         printf(" gstore %d\n", stg_index);
       break;

    case sldrb:
       if ( stg_index )
         printf(" stg%d", stg_index);
        printf(" sldrb %s\n", name.c_str());
       break;
    case ldrb:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" ldrb\n");
       else
         printf(" ldrb exported %s\n", name.c_str());
       break;
    case gldrb:
         printf(" gldrb %d\n", stg_index);
       break;

    case sldrh:
       if ( stg_index )
         printf(" stg%d", stg_index);
        printf(" sldrh %s\n", name.c_str());
       break;
    case ldrh:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" ldrh\n");
       else
         printf(" ldrh exported %s\n", name.c_str());
       break;
    case gldrh:
         printf(" gldrh %d\n", stg_index);
       break;

    case sstrb:
       if ( stg_index )
         printf(" stg%d", stg_index);
        printf(" sstrb %s\n", name.c_str());
       break;
    case strb:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" strb\n");
       else
         printf(" strb exported %s\n", name.c_str());
       break;
    case gstrb:
         printf(" gstrb %d\n", stg_index);
       break;

    case sstrh:
       if ( stg_index )
         printf(" stg%d", stg_index);
        printf(" sstrh exported %s\n", name.c_str());
       break;
    case strh:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( name.empty() )
         printf(" strh\n");
       else
         printf(" strh exported %s\n", name.c_str());
       break;
    case gstrh:
         printf(" gstrh: %d\n", stg_index);
       break;

    case ldr_guid:
         printf(" guid");
         for ( size_t i = 0; i < _countof(guid); i++ )
           printf(" %2.2X", guid[i]);
         if ( value_count )
           printf(" count %d\n", value_count);
         else
           printf("\n");
       break;
    case ldr_rdata:
         printf(" rdata");
         for ( size_t i = 0; i < _countof(rconst); i++ )
           printf(" %2.2X", rconst[i]);
         if ( value_count )
           printf(" count %d\n", value_count);
         else
           printf("\n");
       break;
    case ldr_off:
         if ( value_count )
           printf(" const %X count %d\n", value, value_count);
         else
           printf(" const %X\n", value);
       break;
    case ldr64_off:
         if ( value_count )
           printf(" const %I64X count %d\n", value64, value_count);
         else
           printf(" const %I64X\n", value64);
       break;
    case limp:
        printf(" limp %s\n", name.c_str());
       break;
    case call_imp:
        printf(" call_imp %s\n", name.c_str());
       break;
    case call_dimp:
        printf(" call_dimp %s\n", name.c_str());
       break;
    case call_exp:
        printf(" call_exp %s\n", name.c_str());
       break;
    case call_icall:
        printf(" call_icall\n");
       break;
    case ldrx:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( -1 == reg_index )
         printf(" ldrx\n");
       else
         printf(" ldrx %d\n", reg_index);
       break;
    case strx:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( -1 == reg_index )
         printf(" strx\n");
       else
         printf(" strx %d\n", reg_index);
       break;
    case addx:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( -1 == reg_index )
         printf(" addx\n");
       else
         printf(" addx %d\n", reg_index);
       break;
    case movx:
       if ( stg_index )
         printf(" stg%d", stg_index);
       if ( -1 == reg_index )
         printf(" movx\n");
       else
         printf(" movx %d\n", reg_index);
       break;
    case rule:
        printf(" at %d rule %d\n", at, reg_index);
       break;
    default:
        printf(" unknown type %d\n", type);
  }
}
