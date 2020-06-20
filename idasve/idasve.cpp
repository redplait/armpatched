#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <stdlib.h>
#include "../source/adefs.h"
// #include "arm.hpp"

enum RegNo
{
  R0, R1,  R2,  R3,  R4,  R5,  R6,  R7,
  R8, R9, R10, R11, R12, R13, R14, R15,
  CPSR, CPSR_flg,
  SPSR, SPSR_flg,
  T, rVcs, rVds,         // virtual registers for code and data segments
  Racc0,                 // Intel xScale coprocessor accumulator
  FPSID, FPSCR, FPEXC,   // VFP system registers
  FPINST, FPINST2, MVFR0, MVFR1,
  // msr system registers
  SYSM_APSR,
  SYSM_IAPSR,
  SYSM_EAPSR,
  SYSM_XPSR,
  SYSM_IPSR,
  SYSM_EPSR,
  SYSM_IEPSR,
  SYSM_MSP,
  SYSM_PSP,
  SYSM_PRIMASK,
  SYSM_BASEPRI,
  SYSM_BASEPRI_MAX,
  SYSM_FAULTMASK,
  SYSM_CONTROL,
  Q0,  Q1,   Q2,  Q3,  Q4,  Q5,  Q6,  Q7,
  Q8,  Q9,  Q10, Q11, Q12, Q13, Q14, Q15,
  D0,  D1,   D2,  D3,  D4,  D5,  D6,  D7,
  D8,  D9,  D10, D11, D12, D13, D14, D15,
  D16, D17, D18, D19, D20, D21, D22, D23,
  D24, D25, D26, D27, D28, D29, D30, D31,
  S0,  S1,   S2,  S3,  S4,  S5,  S6,  S7,
  S8,  S9,  S10, S11, S12, S13, S14, S15,
  S16, S17, S18, S19, S20, S21, S22, S23,
  S24, S25, S26, S27, S28, S29, S30, S31,
  FIRST_FPREG=Q0,
  LAST_FPREG=S31,
  CF, ZF, NF, VF,

  // AArch64 registers
  // general-purpose registers
  X0,  X1,  X2,   X3,  X4,  X5,  X6,  X7,
  X8,  X9,  X10, X11, X12, X13, X14, X15,
  X16, X17, X18, X19, X20, X21, X22, X23,
  X24, X25, X26, X27, X28,
  X29, XFP = X29, // frame pointer
  X30, XLR = X30, // link register

  XZR, // zero register (special case of GPR=31)

  XSP, // stack pointer (special case of GPR=31)

  XPC, // PC (not available as actual register)

  // 128-bit SIMD registers
  V0,  V1,  V2,   V3,  V4,  V5,  V6,  V7,
  V8,  V9,  V10, V11, V12, V13, V14, V15,
  V16, V17, V18, V19, V20, V21, V22, V23,
  V24, V25, V26, V27, V28, V29, V30, V31,

  ARM_MAXREG,            // must be the last entry
};

/* opcode names */
static const char *const sve_table[] = {
#include "e.h"
};

extern "C" int __cdecl ArmadilloDisassemble(unsigned int opcode, uint64 PC, struct ad_insn *out);
extern "C" unsigned int __cdecl bits(unsigned int, unsigned int start, unsigned int end);

static size_t idaapi dirty_sve_extension_callback(void *user_data, int event_id, va_list va)
{
  struct ad_insn dis;
  switch ( event_id )
  {
    case processor_t::ev_out_insn:
    {
      int latch = 0;
      outctx_t *ctx = va_arg(va, outctx_t *);
      const insn_t &insn = ctx->insn;
      if (insn.itype < CUSTOM_INSN_ITYPE)
        return 0;
      ctx->out_line(sve_table[insn.itype - CUSTOM_INSN_ITYPE], COLOR_INSN);
      for (int i = 0; i < UA_MAXOP; i++)
      {
        if (!insn.ops[i].type)
          break;
        if ( !latch )
        {
          ctx->out_symbol(' ');
          latch++;
        } else {
          ctx->out_symbol(',');
        }
        if (insn.ops[i].type == o_imm)
          ctx->out_long(insn.ops[i].value, 16);
        else if (insn.ops[i].type == o_reg)
        {
          char buf[10];
          if (insn.ops[i].reg < ARM_MAXREG)
          {
            _snprintf(buf, sizeof(buf), "X%d", insn.ops[i].reg - X0);
            ctx->out_register(buf);
          }
          else if (insn.ops[i].reg < 32 + ARM_MAXREG)
          {
            _snprintf(buf, sizeof(buf), "Z%d", insn.ops[i].reg - ARM_MAXREG);
            ctx->out_register(buf);
          }
          else {
            _snprintf(buf, sizeof(buf), "P%d", insn.ops[i].reg - ARM_MAXREG - 32);
            ctx->out_register(buf);
          }
        }
      }
      return 1;
    }
     break;

    case processor_t::ev_ana_insn:
      {
        insn_t *insn = va_arg(va, insn_t *);
        unsigned op = get_dword(insn->ea);
        unsigned is_our = bits(op, 25, 28);
        if (is_our != 2)
          return 0;
        if ( !ArmadilloDisassemble(op, (uint64)insn->ea, &dis))
        {
          msg("%a %s\n", insn->ea, dis.decoded);
          insn->size = (uint16)4;
          insn->itype = CUSTOM_INSN_ITYPE + dis.instr_id;
          insn->flags |= INSN_64BIT;
          for ( int i = 0; i < dis.num_operands && i < UA_MAXOP; i++ )
          {
            if ( dis.operands[i].type == AD_OP_IMM )
            {
              insn->ops[i].type = o_imm;
              insn->ops[i].value = (uval_t)dis.operands[i].op_imm.bits;
            } else if ( dis.operands[i].type == AD_OP_REG )
            {
              insn->ops[i].type = o_reg;
              insn->ops[i].dtype = dt_qword;
              insn->ops[i].set_shown();
              if ( dis.operands[i].op_reg.sz == 8 )
                insn->ops[i].dtype = dt_byte;
              else if ( dis.operands[i].op_reg.sz == 16 )
                insn->ops[i].dtype = dt_word;
              else if ( dis.operands[i].op_reg.sz == 32 )
                insn->ops[i].dtype = dt_dword;
              if ( !dis.operands[i].op_reg.fp )
              {
                insn->ops[i].reg = X0 + dis.operands[i].op_reg.rn;
              } else if ( dis.operands[i].op_reg.fp == 2 )
              {
                // Zx - between ARM_MAXREG and ARM_MAXREG + 32
                insn->ops[i].reg = dis.operands[i].op_reg.rn + ARM_MAXREG;
              } else if ( dis.operands[i].op_reg.fp == 3 )
              {
                // Px - between ARM_MAXREG + 32 and ARM_MAXREG + 64
                insn->ops[i].reg = dis.operands[i].op_reg.rn + 32 + ARM_MAXREG;
              }
            }
          }
          return int(4); // event processed
        }
      }
      break;

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        op_t *op  = va_arg(va, op_t *);
        if ( (op->type == o_reg) &&
             (op->reg > ARM_MAXREG)
           )
        {
          char buf[6];
          if ( op->reg > 32 + ARM_MAXREG )
          {
             _snprintf(buf, sizeof(buf), "P%d", op->reg - 32 - ARM_MAXREG);
             ctx->out_line(buf, COLOR_INSN);
             return 1;
          } else if ( op->reg > ARM_MAXREG )
          {
            _snprintf(buf, sizeof(buf), "Z%d", op->reg - 32 - ARM_MAXREG);
            ctx->out_line(buf, COLOR_INSN);
            return 1;
          }
        }
        return 0;
      }
      break;

    case processor_t::ev_out_mnem:
    {
      outctx_t *ctx = va_arg(va, outctx_t *);
      const insn_t &insn = ctx->insn;
      if ((insn.itype >= CUSTOM_INSN_ITYPE) &&
        (insn.itype - CUSTOM_INSN_ITYPE) < _countof(sve_table)
        )
      {
        ctx->out_line(sve_table[insn.itype - CUSTOM_INSN_ITYPE], COLOR_INSN);
        return 1;
      }
    }
      break;
  }
  return 0;                     // event is not processed
}

static bool hooked = false;
static netnode nec_node;
static const char node_name[] = "$ idasve plugin";

int idaapi init(void)
{
  if ( ph.id != PLFM_ARM ) return PLUGIN_SKIP;
  nec_node.create(node_name);
  hooked = nec_node.altval(0);
  if ( hooked )
  {
    hook_to_notification_point(HT_IDP, (hook_cb_t *)dirty_sve_extension_callback, NULL);
    msg("sve processor extender is enabled\n");
    return PLUGIN_KEEP;
  }
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, (hook_cb_t *)dirty_sve_extension_callback);
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

bool idaapi run(size_t /*arg*/)
{
  if ( hooked )
    unhook_from_notification_point(HT_IDP, (hook_cb_t *)dirty_sve_extension_callback);
  else
    hook_to_notification_point(HT_IDP, (hook_cb_t *)dirty_sve_extension_callback, NULL);
  hooked = !hooked;
  nec_node.create(node_name);
  nec_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "sve processor extender now is %s", hooked ? "enabled" : "disabled");
  return true;
}

//--------------------------------------------------------------------------
char comment[] = "arm64 sve opcodes processor extender plugin";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "arm64 sve opcodes processor extender";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

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

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  NULL,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
