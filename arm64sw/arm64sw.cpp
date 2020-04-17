#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include "../source/adefs.h"

extern "C" int __cdecl ArmadilloDisassemble(unsigned int opcode, uint64 PC, struct ad_insn *out);

void idaapi
rp_set_comment(ea_t ea, const char *comment, bool is_before, bool rptbl)
{
   if ( NULL == comment || ! *comment )
    return;
   ssize_t cmt_size = get_cmt(ea, rptbl, NULL, 0);
   if ( !cmt_size || -1 == cmt_size )
   {
      set_cmt(ea, comment, rptbl);
      return;
   }
   char *old_cmt = (char *)qalloc(cmt_size + 1);
   get_cmt(ea, rptbl, old_cmt, cmt_size);
   if ( NULL != strstr(old_cmt, comment) )
   {
     qfree(old_cmt);
     return;
   }
   if ( is_before )
   {
     int cl = strlen(comment);
     char *a = (char *)qalloc(cl + 2 + strlen(old_cmt));
     strcpy(a, comment);
     a[cl] = ',';
     strcpy(a+cl+1, old_cmt);
     set_cmt(ea, a, rptbl);
     qfree(a);
   } else
   {
     append_cmt(ea, "," , rptbl );
     append_cmt(ea, comment, rptbl );
   }
   qfree(old_cmt);
}

char arm64sw_comment[] = "switch tables analyzer for arm64 code for windows";
char arm64sw_help[] =
 "arm64 switch tables analyzer plugin\n"
  "\n"
  "This plugin analyses switch tables for arm64 processors family on windows";
char arm64sw_wanted_name[] = "arm64sw plugin";
char arm64sw_wanted_hotkey[] = "Alt-S";

void idaapi
arm64sw_run(int arg)
{
  ea_t addr = get_screen_ea();
  // lets see if we called on code or on data
  ea_t tab = BADADDR;
  flags_t f = get_flags_novalue(addr);
  if ( isData(f) || isTail(f) || isUnknown(f) )
  {
    ea_t xref;
    segment_t *cs = getseg(addr);
    if ( NULL == cs )
      return;
    // round address to 2 ^ 2 bcs this is table of DWORDs
    addr &= ~0x3I64;
    // try find start of this switch table
    do
    {
      xref = get_first_dref_to(addr);
      if ( xref != BADADDR )
      {
        tab = addr;
        break;
      }
      addr -= 4;
      f = get_flags_novalue(addr);
//      msg("%a: flags %X\n", addr, f);
      if ( !(isData(f) || isTail(f) || isUnknown(f)) )
        break;
    } while(addr >= cs->startEA);
    if ( xref == BADADDR )
      return;
    msg("found xref to switch table at %a\n", xref);
    tab = addr;
    addr = xref;
    f = get_flags_novalue(addr);
  }
  if ( !isCode(f) )
    return;
  segment_t *cs = getseg(addr);
  if ( cs == NULL )
    return;
  ea_t base = NULL;
  int tab_size = 0;
  // lets find several things with disasm
  // cmp reg, imm - table size
  // adr reg, table
  // add reg, base
  ea_t curr = addr;
  struct ad_insn dis;
  int i;
  // move backward, search for cmp reg, imm
  for ( i = 0; curr >= cs->startEA && i < 15; i++, curr -= 4 )
  {
    if ( ArmadilloDisassemble(get_long(curr), curr, &dis) )
      return;
    if ( dis.instr_id == AD_INSTR_CMP &&
         dis.num_operands == 2 && 
         dis.operands[0].type == AD_OP_REG && 
         dis.operands[1].type == AD_OP_IMM
       )
    {
      tab_size = (int)dis.operands[1].op_imm.bits;
      curr += 4;
      break;
    }
  }
  if ( !tab_size )
    return;
  int adr_num = 0;
  // move forward, search for adr reg, imm
  for ( i = 0; curr < cs->endEA && i < 15; i++, curr += 4 )
  {
    f = get_flags_novalue(addr);
    if ( !isCode(f) )
      return;
    if ( ArmadilloDisassemble(get_long(curr), curr, &dis) )
      return;
    // adr reg, imm
    if ( dis.instr_id == AD_INSTR_ADR &&
         dis.num_operands == 2 && 
         dis.operands[0].type == AD_OP_REG && 
         dis.operands[1].type == AD_OP_IMM
       )
    {
      if ( !adr_num )
      {
        adr_num++;
        tab = dis.operands[1].op_imm.bits;
        continue;
      }
      if ( adr_num )
      {
        base = dis.operands[1].op_imm.bits;
        break;
      }
    }
  }
  // ok, we have all
  msg("base %a, tab %a, size %X\n", base, tab, tab_size);
  if ( base == BADADDR || tab == BADADDR )
    return;
  for ( int idx = 0; idx <= tab_size; idx++ )
  {
    ea_t curr_case = tab + idx * 4;
    doDwrd(curr_case, 4);
    int offset = 4 * (int)get_long(curr_case);
    ea_t item = base + offset;
    // check if we have just b addr at this address
    if ( !ArmadilloDisassemble(get_long(item), item, &dis) &&
         dis.instr_id == AD_INSTR_B &&
         dis.cc == AD_NONE && 
         dis.num_operands == 1 && 
         dis.operands[0].type == AD_OP_IMM 
       )
      item = dis.operands[0].op_imm.bits;
    char cmt[100];
    qsnprintf(cmt, sizeof(cmt), "%d: %a", idx, item);
    rp_set_comment(curr_case, cmt, false, false);
    add_dref(curr_case, item, dr_O);
  }
}

int idaapi
arm64sw_init(void)
{
 // we must be inside PE
 if ( inf.filetype != f_PE )
   return PLUGIN_SKIP;
 if ( ph.id != PLFM_ARM )
   return PLUGIN_SKIP;
 return PLUGIN_OK;
}

/*
 * PLUGIN description
 */
extern "C" plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                      // plugin flags - ???
  arm64sw_init,           // initialize function
  NULL,                   // terminate. this pointer may be NULL.
  arm64sw_run,            // invoke plugin
  arm64sw_comment,        // long comment about the plugin
  arm64sw_help,           // multiline help about the plugin
  arm64sw_wanted_name,    // the preferred short name of the plugin
  arm64sw_wanted_hotkey   // the preferred hotkey to run the plugin
};
