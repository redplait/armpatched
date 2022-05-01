#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <stdlib.h>
#include <queue>
#include <future>
#include "../source/adefs.h"
#include "../ldr/tpool.h"

extern "C" int __cdecl ArmadilloDisassemble(unsigned int opcode, uint64 PC, struct ad_insn *out);

void idaapi
rp_set_comment(ea_t ea, const char *comment, bool is_before, bool rptbl)
{
   if ( NULL == comment || ! *comment )
    return;
   qstring curr_cmt;
   ssize_t cmt_size = get_cmt(&curr_cmt, ea, rptbl);
   if ( !cmt_size || -1 == cmt_size )
   {
      set_cmt(ea, comment, rptbl);
      return;
   }
   // check if this comment already was added
   if ( NULL != strstr(curr_cmt.c_str(), comment) )
     return;
   if ( is_before )
   {
     int cl = strlen(comment);
     char *a = (char *)qalloc(cl + 2 + curr_cmt.length());
     strcpy(a, comment);
     a[cl] = ',';
     strcpy(a+cl+1, curr_cmt.c_str());
     set_cmt(ea, a, rptbl);
     qfree(a);
   } else
   {
     append_cmt(ea, "," , rptbl );
     append_cmt(ea, comment, rptbl );
   }
}

struct poor_stat
{
  uint64 probes;
  uint64 found;
  uint64 patched;

  poor_stat()
   : probes(0), found(0), patched(0)
  { }
  poor_stat &operator+=(const poor_stat &rhs)
  {
    probes  += rhs.probes;
    found   += rhs.found;
    patched += rhs.patched;
    return *this;
  }
};

// some global state for multi-threaded version
// it seems that IDA itself is not thread-safe - I got lots of internal errors from functions like netnode_supdel
// But if your patience is greater than mine you can set has_multithreaded to 1 and continue debugging
int has_multithreaded = 0;
std::mutex gMutex;
int is_multithreaded = 0;

poor_stat process_func(func_t *f)
{
  struct ad_insn dis;
  poor_stat stat;
  for ( ea_t addr = f->start_ea; addr < f->end_ea; addr += 4 )
  {
    unsigned int val = get_dword(addr);
    // check for add
    if ( (val & 0x7f000000) != 0x11000000 )
      continue;
    if ( ArmadilloDisassemble(val, addr, &dis) )
      break;
    if ( dis.instr_id != AD_INSTR_ADD )
      continue;
    if ( dis.num_operands != 3 )
      continue;
    if ( (dis.operands[0].type != AD_OP_REG) ||
         (dis.operands[1].type != AD_OP_REG) ||
         (dis.operands[2].type != AD_OP_IMM)
       )
     continue;
    // check if this instruction already have xref
    ea_t data = NULL;
    if (is_multithreaded)
    {
      std::unique_lock<std::mutex> lock(gMutex);
      data = get_first_dref_from(addr);
    } else
      data = get_first_dref_from(addr);
    if ( data != BADADDR )
      continue;
#ifdef _DEBUG
    msg("find at %a\n", addr);
#endif /* _DEBUG */
    stat.probes++;
    // store offset and second register
    int treg = dis.operands[1].op_reg.rn;
    unsigned int off = (unsigned int)dis.operands[2].op_imm.bits;
    // yes, this is add reg, regN, imm
    // now try to track back to regN initializing
    ea_t found = BADADDR;
    ea_t back = addr - 4;
    for ( ; back >= f->start_ea; back -= 4 )
    {
      // check if we have code xref on this instruction
      ea_t xto = get_next_cref_to(back, back - 4);
      if (xto != BADADDR)
      {
#ifdef _DEBUG
        msg("%a: xto: %a\n", back, xto);
#endif /* _DEBUG */
        goto next;
      }
      if ( ArmadilloDisassemble(get_dword(back), back, &dis) )
       goto next;
//      msg("%a: %s\n", back, dis.decoded);
      // check if some instruction change treg
      switch(dis.instr_id)
      {
        case AD_INSTR_TBNZ:
        case AD_INSTR_TBZ:
        case AD_INSTR_CBNZ:
        case AD_INSTR_CBZ:
        case AD_INSTR_BL:
        case AD_INSTR_BLR:
        case AD_INSTR_B:
        case AD_INSTR_BRK:
        case AD_INSTR_BR:
        case AD_INSTR_RET:
        case AD_INSTR_MSR:
          goto next;

        case AD_INSTR_YIELD:
        case AD_INSTR_STCLR:
        case AD_INSTR_STR:
        case AD_INSTR_STNP:
        case AD_INSTR_STTR:
        case AD_INSTR_STTRB:
        case AD_INSTR_STTRH:
        case AD_INSTR_STLR:
        case AD_INSTR_STRB:
        case AD_INSTR_STLRB:
        case AD_INSTR_STRH:
        case AD_INSTR_STUR:
        case AD_INSTR_STURB:
        case AD_INSTR_STURH:
        case AD_INSTR_STP:
        case AD_INSTR_CMP:
        case AD_INSTR_CCMP:
        case AD_INSTR_CCMN:
        case AD_INSTR_CAS:
        case AD_INSTR_CASA:
        case AD_INSTR_CASPL:
        case AD_INSTR_CASAB:
        case AD_INSTR_CASAH:
        case AD_INSTR_CASAL:
        case AD_INSTR_CASALB:
        case AD_INSTR_CASALH:
        case AD_INSTR_DMB:
        case AD_INSTR_DSB:
        case AD_INSTR_ISB:
        case AD_INSTR_NOP:
        case AD_INSTR_TST:
        case AD_INSTR_STSET:
        case AD_INSTR_PRFM:
          break;

        case AD_INSTR_LDP:
        case AD_INSTR_LDNP:
        case AD_INSTR_LDPSW:
         if ( dis.num_operands >= 3 && (dis.operands[0].type == AD_OP_REG) &&
               (dis.operands[1].type == AD_OP_REG)
            )
          {
            if ( (dis.operands[0].op_reg.rn == treg) || (dis.operands[1].op_reg.rn == treg) )
              goto next;
          }
          break;

        case AD_INSTR_LDTR:
        case AD_INSTR_LDTRB:
        case AD_INSTR_LDTRH:
        case AD_INSTR_LDRSW:
        case AD_INSTR_LDRSH:
        case AD_INSTR_LDR:
        case AD_INSTR_LDAR:
        case AD_INSTR_LDARB:
        case AD_INSTR_LDARH:
        case AD_INSTR_LDRB:
        case AD_INSTR_LDRSB:
        case AD_INSTR_LDRH:
        case AD_INSTR_LDUR:
        case AD_INSTR_LDURB:
        case AD_INSTR_LDURH:
        case AD_INSTR_LDURSW:
        case AD_INSTR_MOV:
        case AD_INSTR_ADRP:
        case AD_INSTR_EON:
        case AD_INSTR_EOR:
        case AD_INSTR_ORR:
        case AD_INSTR_ORN:
        case AD_INSTR_AND:
        case AD_INSTR_ANDS:
        case AD_INSTR_MSUB:
        case AD_INSTR_SUB:
        case AD_INSTR_UMSUBL:
        case AD_INSTR_SUBS:
        case AD_INSTR_MOVK:
        case AD_INSTR_MADD:
        case AD_INSTR_ADDS:
        case AD_INSTR_ADC:
        case AD_INSTR_ADCS:
        case AD_INSTR_CMN:
        case AD_INSTR_STADD:
        case AD_INSTR_UMADDL:
        case AD_INSTR_SMADDL:
        case AD_INSTR_UDIV:
        case AD_INSTR_SDIV:
        case AD_INSTR_MUL:
        case AD_INSTR_UMULL:
        case AD_INSTR_UMULH:
        case AD_INSTR_SMULL:
        case AD_INSTR_SMULH:
        case AD_INSTR_SBFX:
        case AD_INSTR_SXTW:
        case AD_INSTR_SXTB:
        case AD_INSTR_SXTH:
        case AD_INSTR_CSEL:
        case AD_INSTR_MRS:
        case AD_INSTR_LSL:
        case AD_INSTR_LSLV:
        case AD_INSTR_LSR:
        case AD_INSTR_LSRV:
        case AD_INSTR_CSET:
        case AD_INSTR_CSETM:
        case AD_INSTR_UBFIZ:
        case AD_INSTR_SBFIZ:
        case AD_INSTR_BIC:
        case AD_INSTR_ASR:
        case AD_INSTR_ASRV:
        case AD_INSTR_BFI:
        case AD_INSTR_CNEG:
        case AD_INSTR_NEG:
        case AD_INSTR_NEGS:
        case AD_INSTR_CSNEG:
        case AD_INSTR_CSINC:
        case AD_INSTR_CINC:
        case AD_INSTR_CSINV:
        case AD_INSTR_CINV:
        case AD_INSTR_UBFX:
        case AD_INSTR_BFXIL:
        case AD_INSTR_ROR:
        case AD_INSTR_MVN:
        case AD_INSTR_CLS:
        case AD_INSTR_CLZ:
        case AD_INSTR_RBIT:
        case AD_INSTR_REV:
        case AD_INSTR_REV16:
        case AD_INSTR_EXTR:
        case AD_INSTR_LDADDAL:
        case AD_INSTR_LDADDL:
         if ( (dis.operands[0].type == AD_OP_REG) && (dis.operands[0].op_reg.rn == treg) )
           goto next;
         break;
        case AD_INSTR_ADD:
          if ( dis.num_operands == 3 && (dis.operands[0].type == AD_OP_REG) &&
               (dis.operands[1].type == AD_OP_REG) &&
               (dis.operands[2].type == AD_OP_IMM)
             )
          {
            if ( dis.operands[0].op_reg.rn != treg )
              continue;
            if ( is_multithreaded )
            {
              std::unique_lock<std::mutex> lock(gMutex);
              found = get_first_dref_from(back);
            } else
              found = get_first_dref_from(back);
#ifdef _DEBUG
            msg("%a: add %d treg %d found %a\n", back, dis.operands[0].op_reg.rn, treg, found);
#endif /* _DEBUG */
            goto found;
          }
         break;
        default:
         msg("%a %s - unknown instruction\n", back, dis.decoded);
         goto next;
      }
    }
found:
#ifdef _DEBUG
    msg("%a: found %a\n", back, found);
#endif /* _DEBUG */
    stat.found++;
    if ( found == BADADDR )
      continue;
    // we have address where found was found in back
    char cmt[100];
    qsnprintf(cmt, sizeof(cmt), "%a", found + off);
    if ( is_multithreaded )
    {
      std::unique_lock<std::mutex> lock(gMutex);
      del_dref(back, found);
      add_dref(addr, found + off, dr_O);
      rp_set_comment(addr, cmt, false, false);
    } else {
      del_dref(back, found);
      add_dref(addr, found + off, dr_O);
      rp_set_comment(addr, cmt, false, false);
    }
    stat.patched++;
next:
    ;
  }
  return stat;
}

void dump_stat(const poor_stat &rhs)
{
  msg("poorgcc: probes %I64d found %I64d patched %I64d\n", rhs.probes, rhs.found, rhs.patched);
}

bool idaapi run(size_t arg)
{
  if ( !arg )
  {
    ea_t addr = get_screen_ea();
    func_t *f = get_func(addr);
    if ( f == NULL )
      return false;
    dump_stat(process_func(f));
  } else {
    poor_stat stat;
    // process all functions
    size_t fcount = get_func_qty();
    // check how many processors we have
    int proc_num = std::thread::hardware_concurrency();
msg("proc_num %d (%d) fcount %d\n", proc_num, proc_num * 100, fcount);
    if ( !has_multithreaded || (proc_num < 2) || (proc_num * 100 > fcount) )
    {
      for ( size_t n = 0; n < fcount; n++ )
      {
        func_t *f = getn_func(n);
        if ( f == NULL )
          continue;
        stat += process_func(f);
      }
      dump_stat(stat);
    } else {
      // use thread pool
      thread_pool<poor_stat> pool(proc_num);
      is_multithreaded = 1;
      int idx = 0;
      size_t n = 0;
      std::vector<std::future<poor_stat> > futures(proc_num);
      for ( ; n < fcount; n++ )
      {
         func_t *f = getn_func(n);
         if ( f == NULL )
           continue;
         if ( idx < proc_num )
         {
           std::packaged_task<poor_stat()> job([=] {
              return process_func(f);
            }
           );
           futures[idx++] = std::move(pool.add(job));
           continue;
         }
         // harvest
         for ( idx = 0; idx < proc_num; idx++ )
           stat += futures[idx].get();
         idx = 0;
      }
      // harvest remaining
      for ( ; idx > 0; idx-- )
        stat += futures[idx-1].get();
      dump_stat(stat);
    }
  }
}

int idaapi init(void)
{
  if ( ph.id != PLFM_ARM ) return PLUGIN_SKIP;
  return PLUGIN_OK;
}

char comment[] = "arm64 poor gcc code fix plugin";
char wanted_name[] = "arm64 poor gcc code fixer";

char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  NULL,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  NULL,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
