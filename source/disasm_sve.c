#include <stdio.h>
#include <stdlib.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

static int get_tsz(unsigned size)
{
  if ( size & 1 )
    return _8_BIT;
  if ( size & 2 )
    return _16_BIT;
  if ( size & 4 )
    return _32_BIT;
  if ( size & 8 )
    return _64_BIT;
  if ( size & 16 )
    return _128_BIT;
  return 0;
}

static int get_sz(unsigned size)
{
  switch(size)
  {
    case 0:
      return _8_BIT;
    case 1:
      return _16_BIT;
    case 2:
      return _32_BIT;
    case 3:
      return _64_BIT;
  }
  return 0;
}

static const struct itab max_min[] = {
/* 00 U0 */ { "smax", AD_INSTR_SMAX },
/* 00 U1 */ { "umax", AD_INSTR_UMAX },
/* 01 U0 */ { "smin", AD_INSTR_SMIN },
/* 01 U1 */ { "umin", AD_INSTR_UMIN },
/* 10 U0 */ { "sabd", AD_INSTR_SABD },
/* 10 U1 */ { "uabd", AD_INSTR_UABD },
};

static const struct itab bshift_tab[] = {
/* 00 0 0 */ { "asr", AD_INSTR_ASR },
/* 00 0 1 */ { "lsr", AD_INSTR_LSR },
/* 00 0 1 */ { NULL, AD_NONE },
/* 00 1 1 */ { "lsl", AD_INSTR_LSL },
/* 01 0 0 */ { "asrd", AD_INSTR_ASRD },
/* 01 0 1 */ { NULL, AD_NONE },
/* 01 1 0 */ { "sqshl", AD_INSTR_SQSHL },
/* 01 1 1 */ { "uqshl", AD_INSTR_UQSHL },
/* 10 0 0 */ { NULL, AD_NONE },
/* 10 0 1 */ { NULL, AD_NONE },
/* 10 1 0 */ { NULL, AD_NONE },
/* 10 1 1 */ { NULL, AD_NONE },
/* 11 0 0 */ { "srshr", AD_INSTR_SRSHR },
/* 11 0 1 */ { "urshr", AD_INSTR_URSHR },
/* 11 1 0 */ { NULL, AD_NONE },
/* 11 1 1 */ { "sqshlu", AD_INSTR_SQSHLU },
};

static const struct itab bshift_tab2[] = {
/* 0 0 0 */ { "asr", AD_INSTR_ASR },
/* 0 0 1 */ { "lsr", AD_INSTR_LSR },
/* 0 1 0 */ { NULL, AD_NONE },
/* 0 1 1 */ { "lsl", AD_INSTR_LSL },
/* 1 0 0 */ { "asrr", AD_INSTR_ASRR },
/* 1 0 1 */ { "lsrr", AD_INSTR_LSRR },
/* 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 */ { "lslr", AD_INSTR_LSLR },
};

static const struct itab bun_tab[] = {
/* 0 0 0 */ { "cls", AD_INSTR_CLS },
/* 0 0 1 */ { "clz", AD_INSTR_CLZ },
/* 0 1 0 */ { "cnt", AD_INSTR_CNT },
/* 0 1 1 */ { "cnot", AD_INSTR_CNOT },
/* 1 0 0 */ { "fabs", AD_INSTR_FABS },
/* 1 0 1 */ { "fneg", AD_INSTR_FNEG },
/* 1 1 0 */ { "not", AD_INSTR_NOT },
/* 1 1 1 */ { NULL, AD_NONE },
};

static int op00_op10_op20(struct instruction *i, struct ad_insn *out)
{
  unsigned op3 = bits(i->opcode, 10, 15);
  // op3 x1xxxx
  if ( (op3 & 0x10) == 0x10 )
  {
    // SVE Integer Multiply-Add - Predicated
    unsigned op0 = bits(i->opcode, 15, 15);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned op = bits(i->opcode, 13, 13);
    int sz = get_sz(size);
    if ( !op0 )
    {
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zda = bits(i->opcode, 0, 4);
      const char *instr_s = NULL;

      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      if ( !op )
      {
        SET_INSTR_ID(out, AD_INSTR_MLA);
        instr_s = "mla";
      }
      else
      {
        SET_INSTR_ID(out, AD_INSTR_MLS);
        instr_s = "mls";
      }

      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zm], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zda]);
      return 0;
    } else {
      unsigned Za = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      const char *instr_s = NULL;

      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Za);
      ADD_FIELD(out, Zdn);

      if ( !op )
      {
        SET_INSTR_ID(out, AD_INSTR_MAD);
        instr_s = "mad";
      }
      else
      {
        SET_INSTR_ID(out, AD_INSTR_MSB);
        instr_s = "msb";
      }

      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Za, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zm], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Za], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
  } else // op3 000xxx
  if ( !(op3 >> 3) )
  {
    // SVE Integer Binary Arithmetic - Predicated
    unsigned op0 = bits(i->opcode, 18, 20);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned Zm = bits(i->opcode, 5, 9);
    int sz = get_sz(size);

    // 00x
    if ( !(op0 & 6) )
    {
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 18);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "add";
                SET_INSTR_ID(out, AD_INSTR_ADD);
            break;
        case 1: instr_s = "sub";
                SET_INSTR_ID(out, AD_INSTR_SUB);
            break;
        case 3: instr_s = "subr";
                SET_INSTR_ID(out, AD_INSTR_SUBR);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    // 01x
    if ( 2 == (op0 & 6) )
    {
      unsigned opcu = bits(i->opcode, 16, 18);
      unsigned Zdn = bits(i->opcode, 0, 4);
      if ( OOB(opcu, max_min) )
        return 1;
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      SET_INSTR_ID(out, max_min[opcu].instr_id);
      concat(DECODE_STR(out), "%s %s, %s, %s", max_min[opcu].instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    // 100 - page 2756
    if ( 4 == op0 )
    {
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned hu = bits(i->opcode, 16, 17);
      const char *instr_s = NULL;
      switch(hu)
      {
        case 0: instr_s = "mul";
                SET_INSTR_ID(out, AD_INSTR_MUL);
            break;
        case 2: instr_s = "smulh";
                SET_INSTR_ID(out, AD_INSTR_SMULH);
            break;
        case 3: instr_s = "umulh";
                SET_INSTR_ID(out, AD_INSTR_UMULH);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    // 101 - page 2756
    if ( 5 == op0 )
    {
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned ru = bits(i->opcode, 16, 17);
      const char *instr_s = NULL;
      switch(ru)
      {
        case 0: instr_s = "sdiv";
                SET_INSTR_ID(out, AD_INSTR_SDIV);
            break;
        case 1: instr_s = "udiv";
                SET_INSTR_ID(out, AD_INSTR_UDIV);
            break;
        case 2: instr_s = "sdivr";
                SET_INSTR_ID(out, AD_INSTR_SDIVR);
            break;
        case 3: instr_s = "udivr";
                SET_INSTR_ID(out, AD_INSTR_UDIVR);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    // 11x - page 2756
    if ( 6 == (op0 & 6) )
    {
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 18);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "orr";
                SET_INSTR_ID(out, AD_INSTR_ORR);
            break;
        case 1: instr_s = "eor";
                SET_INSTR_ID(out, AD_INSTR_EOR);
            break;
        case 2: instr_s = "and";
                SET_INSTR_ID(out, AD_INSTR_AND);
            break;
        case 3: instr_s = "bic";
                SET_INSTR_ID(out, AD_INSTR_BIC);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    return 1;
  } else // op3 001xxx
  if ( 1 == (op3 >> 3) )
  {
    // SVE Integer Reduction
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned Zn = bits(i->opcode, 5, 9);
    int sz = get_sz(size);
    if ( !op0 )
    {
      // SVE integer add reduction (predicated)
      unsigned Vd = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 18);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "saddv";
                SET_INSTR_ID(out, AD_INSTR_SADDV);
            break;
        case 1: instr_s = "uaddv";
                SET_INSTR_ID(out, AD_INSTR_UADDV);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Vd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_FP_V_128[Vd]);
      return 0;
    }
    if ( 1 == op0 )
    {
      // SVE integer min/max reduction (predicated)
      unsigned Vd = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 18);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "smaxv";
                SET_INSTR_ID(out, AD_INSTR_SMAXV);
            break;
        case 1: instr_s = "umaxv";
                SET_INSTR_ID(out, AD_INSTR_UMAXV);
            break;
        case 2: instr_s = "sminv";
                SET_INSTR_ID(out, AD_INSTR_SMINV);
            break;
        case 3: instr_s = "uminv";
                SET_INSTR_ID(out, AD_INSTR_UMINV);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Vd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_FP_V_128[Vd]);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE constructive prefix (predicated)
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 17, 18);
      const char *instr_s = "movprfx";
      if ( opc )
        return 1;
      SET_INSTR_ID(out, AD_INSTR_MOVPRFX);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zd]);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE bitwise logical reduction (predicated)
      unsigned Vd = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 18);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "orv";
                SET_INSTR_ID(out, AD_INSTR_ORV);
            break;
        case 1: instr_s = "eorv";
                SET_INSTR_ID(out, AD_INSTR_EORV);
            break;
        case 2: instr_s = "andv";
                SET_INSTR_ID(out, AD_INSTR_ANDV);
            break;
        default:
          return 1;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Vd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_FP_V_128[Vd]);
      return 0;
    }
    return 1;
  } // op3 100xxx
  if ( 4 == (op3 >> 3) )
  {
    // SVE Bitwise Shift - Predicated
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned size = bits(i->opcode, 22, 23);
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned Zdn = bits(i->opcode, 0, 4);
    int sz = get_sz(size);
    if ( !(op0 & 2) )
    {
      unsigned opc = bits(i->opcode, 16, 19);
      unsigned imm3 = bits(i->opcode, 5, 7);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 8, 9);
      const char *instr_s = NULL;

      if ( bshift_tab[opc].instr_s == NULL )
         return 1;
      size = (tszh << 2) | tszl;
      sz = get_sz(size);
      instr_s = bshift_tab[opc].instr_s;
      SET_INSTR_ID(out, bshift_tab[opc].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);

      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zdn], imm3);
      return 0;
    }
    if ( op0 == 2 )
    {
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zm = bits(i->opcode, 5, 9);
      const char *instr_s = NULL;

      if ( bshift_tab2[opc].instr_s == NULL )
         return 1;

      instr_s = bshift_tab2[opc].instr_s;
      SET_INSTR_ID(out, bshift_tab2[opc].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( op0 == 3 )
    {
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zm = bits(i->opcode, 5, 9);
      const char *instr_s = NULL;
      if ( opc > 3 )
        return 1;
      instr_s = bshift_tab2[opc].instr_s;
      SET_INSTR_ID(out, bshift_tab2[opc].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  } // op3 101xxx
  if ( 5 == (op3 >> 3) )
  {
    // SVE Integer Unary Arithmetic - Predicated 
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);

    if ( op0 < 2 )
      return 1;
    if ( op0 == 3 )
    {
      // bitwise unary
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      const char *instr_s = NULL;

      if ( NULL == bun_tab[opc].instr_s )
        return 1;
      instr_s = bun_tab[opc].instr_s;
      SET_INSTR_ID(out, bun_tab[opc].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( op0 == 2 )
    {
      // SVE integer unary operations (predicated)
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "sxtb";
                SET_INSTR_ID(out, AD_INSTR_SXTB);
         break; 
        case 1: instr_s = "uxtb";
                SET_INSTR_ID(out, AD_INSTR_UXTB);
         break;
        case 2: instr_s = "sxth";
                SET_INSTR_ID(out, AD_INSTR_SXTH);
         break;
        case 3: instr_s = "uxth";
                SET_INSTR_ID(out, AD_INSTR_UXTH);
         break;
        case 4: instr_s = "sxtw";
                SET_INSTR_ID(out, AD_INSTR_SXTW);
         break;
        case 5: instr_s = "uxtw";
                SET_INSTR_ID(out, AD_INSTR_UXTW);
         break;
        case 6: instr_s = "abs";
                SET_INSTR_ID(out, AD_INSTR_ABS);
         break;
        case 7: instr_s = "neg";
                SET_INSTR_ID(out, AD_INSTR_NEG); 
         break;
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab add_sub[] = {
/* 000 */ { "add", AD_INSTR_ADD },
/* 001 */ { "sub", AD_INSTR_SUB },
/* 010 */ { NULL, AD_NONE },
/* 011 */ { NULL, AD_NONE },
/* 100 */ { "sqadd", AD_INSTR_SQADD },
/* 101 */ { "uqadd", AD_INSTR_UQADD },
/* 110 */ { "sqsub", AD_INSTR_SQSUB },
/* 111 */ { "uqsub", AD_INSTR_UQSUB },
};

static const struct itab btern[] = {
/* 000 */ { "eor3", AD_INSTR_EOR3 },
/* 001 */ { "bsl", AD_INSTR_BSL },
/* 010 */ { "bcax", AD_INSTR_BCAX },
/* 011 */ { "bsl1n", AD_INSTR_BSL1N },
/* 100 */ { NULL, AD_NONE },
/* 101 */ { "bsl2n", AD_INSTR_BSL2N },
/* 110 */ { NULL, AD_NONE },
/* 111 */ { "nbsl", AD_INSTR_NBSL },
};

static const struct itab satur_tab[] = {
/* 00 0 0 0 */ { "sqincb", AD_INSTR_SQINCB },
/* 00 0 0 1 */ { "uqincb", AD_INSTR_UQINCB },
/* 00 0 1 0 */ { "sqdecb", AD_INSTR_SQDECB },
/* 00 0 1 1 */ { "uqdecb", AD_INSTR_UQDECB },
/* 00 1 0 0 */ { "sqincb", AD_INSTR_SQINCB },
/* 00 1 0 1 */ { "uqincb", AD_INSTR_UQINCB },
/* 00 1 1 0 */ { "sqdecb", AD_INSTR_SQDECB },
/* 00 1 1 1 */ { "uqdecb", AD_INSTR_UQDECB },
/* 01 0 0 0 */ { "sqinch", AD_INSTR_SQINCH },
/* 01 0 0 1 */ { "uqinch", AD_INSTR_UQINCH },
/* 01 0 1 0 */ { "sqdech", AD_INSTR_SQDECH },
/* 01 0 1 1 */ { "uqdech", AD_INSTR_UQDECH },
/* 01 1 0 0 */ { "sqinch", AD_INSTR_SQINCH },
/* 01 1 0 1 */ { "uqinch", AD_INSTR_UQINCH },
/* 01 1 1 0 */ { "sqdech", AD_INSTR_SQDECH },
/* 01 1 1 1 */ { "uqdech", AD_INSTR_UQDECH },
/* 10 0 0 0 */ { "sqincw", AD_INSTR_SQINCW },
/* 10 0 0 1 */ { "uqincw", AD_INSTR_UQINCW },
/* 10 0 1 0 */ { "sqdecw", AD_INSTR_SQDECW },
/* 10 0 1 1 */ { "uqdecw", AD_INSTR_UQDECW },
/* 10 1 0 0 */ { "sqincw", AD_INSTR_SQINCW },
/* 10 1 0 1 */ { "uqincw", AD_INSTR_UQINCW },
/* 10 1 1 0 */ { "sqdecw", AD_INSTR_SQDECW },
/* 10 1 1 1 */ { "uqdecw", AD_INSTR_UQDECW },
/* 11 0 0 0 */ { "sqincd", AD_INSTR_SQINCD },
/* 11 0 0 1 */ { "uqincd", AD_INSTR_UQINCD },
/* 11 0 1 0 */ { "sqdecd", AD_INSTR_SQDECD },
/* 11 0 1 1 */ { "uqdecd", AD_INSTR_UQDECD },
/* 11 1 0 0 */ { "sqincd", AD_INSTR_SQINCD },
/* 11 1 0 1 */ { "uqincd", AD_INSTR_UQINCD },
/* 11 1 1 0 */ { "sqdecd", AD_INSTR_SQDECD },
/* 11 1 1 1 */ { "uqdecd", AD_INSTR_UQDECD },
};

static const struct itab satur_tab2[] = {
/* 00 0 0 */ { NULL, AD_NONE },
/* 00 0 1 */ { NULL, AD_NONE },
/* 00 1 0 */ { NULL, AD_NONE },
/* 00 1 1 */ { NULL, AD_NONE },
/* 01 0 0 */ { "sqinch", AD_INSTR_SQINCH },
/* 01 0 1 */ { "uqinch", AD_INSTR_UQINCH },
/* 01 1 0 */ { "sqdech", AD_INSTR_SQDECH },
/* 01 1 1 */ { "uqdech", AD_INSTR_UQDECH },
/* 10 0 0 */ { "sqincw", AD_INSTR_SQINCW },
/* 10 0 1 */ { "uqincw", AD_INSTR_UQINCW },
/* 10 1 0 */ { "sqdecw", AD_INSTR_SQDECW },
/* 10 1 1 */ { "uqdecw", AD_INSTR_UQDECW },
/* 11 0 0 */ { "sqincd", AD_INSTR_SQINCD },
/* 11 0 1 */ { "uqincd", AD_INSTR_UQINCD },
/* 11 1 0 */ { "sqdecd", AD_INSTR_SQDECD },
/* 11 1 1 */ { "uqdecd", AD_INSTR_UQDECD },
};

static const struct itab incdec_tab[] = {
/* 00 0 */ { NULL, AD_NONE },
/* 00 1 */ { NULL, AD_NONE },
/* 01 0 */ { "inch", AD_INSTR_INCH },
/* 01 1 */ { "dech", AD_INSTR_DECH },
/* 10 0 */ { "incw", AD_INSTR_INCW },
/* 10 1 */ { "decw", AD_INSTR_DECW },
/* 11 0 */ { "incd", AD_INSTR_INCD },
/* 11 1 */ { "decd", AD_INSTR_DECD },
};

static const struct itab incdec_tab2[] = {
/* 00 0 */ { "incb", AD_INSTR_INCB },
/* 00 1 */ { "decb", AD_INSTR_DECB },
/* 01 0 */ { "inch", AD_INSTR_INCH },
/* 01 1 */ { "dech", AD_INSTR_DECH },
/* 10 0 */ { "incw", AD_INSTR_INCW },
/* 10 1 */ { "decw", AD_INSTR_DECW },
/* 11 0 */ { "incd", AD_INSTR_INCD },
/* 11 1 */ { "decd", AD_INSTR_DECD },
};

static int op00_op10_op21(struct instruction *i, struct ad_insn *out)
{
  unsigned op3 = bits(i->opcode, 10, 15);
  // op3 000xxx
  if ( !(op3 >> 3) )
  {
    // SVE integer add/subtract vectors (unpredicated) 
    unsigned opc = bits(i->opcode, 10, 12);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned op = bits(i->opcode, 13, 13);
    const char *instr_s = add_sub[opc].instr_s;
    if ( instr_s == NULL )
      return 1;
    SET_INSTR_ID(out, add_sub[opc].instr_id); 
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

    concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zd]);
    return 0;
  } else
  // op3 001xxx
  if ( 1 == (op3 >> 3) )
  {
    // SVE Bitwise Logical - Unpredicated - page 2759
    unsigned opc = bits(i->opcode, 10, 12);
    if ( !(opc & 4) )
      return 1;
    if ( opc == 4 )
    {
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      const char *instr_s = NULL;
      opc = bits(i->opcode, 22, 23);
      switch(opc)
      {
        case 0: instr_s = "and";
                SET_INSTR_ID(out, AD_INSTR_AND);
         break;
        case 1: instr_s = "orr";
                SET_INSTR_ID(out, AD_INSTR_ORR);
         break;
        case 2: instr_s = "eor";
                SET_INSTR_ID(out, AD_INSTR_EOR);
         break;
        case 3: instr_s = "bic";
                SET_INSTR_ID(out, AD_INSTR_BIC);
         break;
      }
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zd, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zd]);
      return 0;
    }
    if ( opc == 5 )
    {
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 19, 20);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned size = (tszh << 2) | tszl;
      int sz = get_sz(size);

      SET_INSTR_ID(out, AD_INSTR_XAR);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);

      concat(DECODE_STR(out), "xar %s, %s, %s, #%x", AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm], imm3);
      return 0;
    }
    if ( 3 == (opc >> 1) )
    {
      // SVE2 bitwise ternary operations
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned Zk = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned o2 = bits(i->opcode, 10, 10);
      const char *instr_s = NULL;
      opc = bits(i->opcode, 22, 23);
      opc = (opc << 1) | o2;
      instr_s = btern[opc].instr_s;
      if ( instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, btern[opc].instr_id);

      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zk);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zk, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zk]);
      return 0;

    }
    return 1;
  } else
  // op3 0100xx
  if ( 4 == (op3 >> 2) )
  {
    // SVE Index Generation - page 2761
    unsigned op0 = bits(i->opcode, 10, 11);
    unsigned Zd = bits(i->opcode, 0, 4);
    const char *instr_s = "index";
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    SET_INSTR_ID(out, AD_INSTR_SMAX);
    if ( 0 == op0 )
    {
      unsigned imm5 = bits(i->opcode, 5, 9);
      unsigned imm5b = bits(i->opcode, 16, 20);

      ADD_FIELD(out, imm5b);
      ADD_FIELD(out, imm5);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5b);
      concat(DECODE_STR(out), "%s %s, #%x, #%x", instr_s, AD_RTBL_Z_128[Zd], imm5, imm5b);
      return 0;
    }
    if ( 1 == op0 )
    {
      unsigned imm5 = bits(i->opcode, 16, 20);
      unsigned Rn = bits(i->opcode, 5, 9);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

      ADD_FIELD(out, imm5);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
      concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zd], Rn_s, imm5);
      return 0;
    }
    if ( 2 == op0 )
    {
      unsigned imm5 = bits(i->opcode, 5, 9);
      unsigned Rm = bits(i->opcode, 16, 20);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

      ADD_FIELD(out, Rm);
      ADD_FIELD(out, imm5);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
      ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));

      concat(DECODE_STR(out), "%s %s, #%x, %s", instr_s, AD_RTBL_Z_128[Zd], imm5, Rm_s);
      return 0;
    }
    if ( 3 == op0 )
    {
      unsigned Rm = bits(i->opcode, 16, 20);
      unsigned Rn = bits(i->opcode, 5, 9);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], Rn_s, Rm_s);
      return 0;
    }
    return 1;
  } else
  // op3 0101xx
  if ( 5 == (op3 >> 2) )
  {
    // SVE Stack Allocation - page 2761
    unsigned op0 = bits(i->opcode, 23, 23);
    unsigned op1 = bits(i->opcode, 11, 11);
    if ( op1 )
      return 1;
    if ( !op0 )
    {
      unsigned op = bits(i->opcode, 22, 22);
      unsigned Rn = bits(i->opcode, 16, 20);
      unsigned Rd = bits(i->opcode, 0, 4);
      unsigned imm6 = bits(i->opcode, 5, 10);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      const char *instr_s = NULL;
      if ( !op )
      {
        instr_s = "addvl";
        SET_INSTR_ID(out, AD_INSTR_ADDVL);
      } else {
        instr_s = "addpl";
        SET_INSTR_ID(out, AD_INSTR_ADDPL);
      }
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, imm6);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm6);

      concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, Rd_s, Rn_s, imm6);
      return 0;
    }
    // SVE stack frame size
    if ( 1 == op0 )
    {
      unsigned op2 = bits(i->opcode, 16, 20);
      unsigned Rd = bits(i->opcode, 0, 4);
      unsigned imm6 = bits(i->opcode, 5, 10);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      if ( op2 != 7 )
        return 1;
      SET_INSTR_ID(out, AD_INSTR_RDVL);

      ADD_FIELD(out, imm6);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm6);

      concat(DECODE_STR(out), "rdvl %s, #%x", Rd_s, imm6);
      return 0;
    }
    return 1;
  } else
  // op3 011xxx
  if ( 3 == (op3 >> 3) )
  {
    // SVE2 Integer Multiply - Unpredicated - page 2762
    unsigned op2 = bits(i->opcode, 11, 12);
    if ( 3 == op2 )
      return 1;
    if ( 2 == op2 )
    {
      unsigned R = bits(i->opcode, 10, 10);
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      const char *instr_s = NULL;
      if ( R )
      {
        instr_s = "sqrdmulh";
        SET_INSTR_ID(out, AD_INSTR_SQRDMULH);
      } else {
        instr_s = "sqdmulh";
        SET_INSTR_ID(out, AD_INSTR_SQDMULH);
      }
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    } else {
      unsigned opc = bits(i->opcode, 10, 11);
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "mul";
                SET_INSTR_ID(out, AD_INSTR_MUL);
         break;
        case 2: instr_s = "smulh"; // wtf? where is smul?
                SET_INSTR_ID(out, AD_INSTR_SMULH);
         break;
        case 3: instr_s = "umulh";
                SET_INSTR_ID(out, AD_INSTR_UMULH);
         break;
        case 1: if ( size )
                  return 1;
                instr_s = "pmul";
                SET_INSTR_ID(out, AD_INSTR_PMUL);
         break;
      }
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
  } else
  // op3 100xxx
  if ( 4 == (op3 >> 3) )
  {
    // SVE Bitwise Shift - Unpredicated - page 2763
    unsigned op0 = bits(i->opcode, 12, 12);
    if ( !op0 )
    {
      unsigned opc = bits(i->opcode, 10, 11);
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      const char *instr_s = NULL;
      switch(opc)
      {
        case 0: instr_s = "asr";
                SET_INSTR_ID(out, AD_INSTR_ASR);
         break;
        case 1: instr_s = "lsr";
                SET_INSTR_ID(out, AD_INSTR_LSR);
         break;
        case 3: instr_s = "lsl";
                SET_INSTR_ID(out, AD_INSTR_LSL);
         break;
        default: return 1;
      }
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    } else {
      unsigned opc = bits(i->opcode, 10, 11);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 19, 20);
      unsigned size = (tszh << 2) | tszl;
      int sz = get_sz(size);
      const char *instr_s = NULL;

      switch(opc)
      {
        case 0: instr_s = "asr";
                SET_INSTR_ID(out, AD_INSTR_ASR);
         break;
        case 1: instr_s = "lsr";
                SET_INSTR_ID(out, AD_INSTR_LSR);
         break;
        case 3: instr_s = "lsl";
                SET_INSTR_ID(out, AD_INSTR_LSL);
         break;
        default: return 1;
      }
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], imm3);
      return 0;
    }
  } else
  // op3 1010xxx
  if ( 0xa == (op3 >> 2) )
  {
    // SVE address generation - page 2764
    unsigned opc = bits(i->opcode, 22, 23);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    unsigned msz = bits(i->opcode, 10, 11);
    SET_INSTR_ID(out, AD_INSTR_ADR);

    ADD_FIELD(out, Zm);
    ADD_FIELD(out, msz);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "adr %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  } else
  // op3 1011xxx
  if ( 0xb == (op3 >> 2) )
  {
    // SVE Integer Misc - Unpredicated - page 2764
    unsigned op0 = bits(i->opcode, 10, 11);
    if ( op0 == 3 )
    {
      unsigned opc2 = bits(i->opcode, 16, 20);
      if ( opc2 )
        return 1;
      else {
        unsigned Zn = bits(i->opcode, 5, 9);
        unsigned Zd = bits(i->opcode, 0, 4);
        SET_INSTR_ID(out, AD_INSTR_MOVPRFX);

        ADD_FIELD(out, Zn);
        ADD_FIELD(out, Zd);
        ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        concat(DECODE_STR(out), "movprfx %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
        return 0;
      }
    } else if ( op0 == 2 )
    {
      unsigned opc = bits(i->opcode, 16, 20);
      if ( opc )
        return 1;
      else {
        unsigned Zn = bits(i->opcode, 5, 9);
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);
        SET_INSTR_ID(out, AD_INSTR_FEXPA);

        ADD_FIELD(out, Zn);
        ADD_FIELD(out, Zd);
        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        concat(DECODE_STR(out), "fexpa %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
        return 0;
      }
    } else {
      unsigned op = bits(i->opcode, 10, 10);
      if ( op )
        return 1;
      else {
        unsigned Zm = bits(i->opcode, 16, 20);
        unsigned Zn = bits(i->opcode, 5, 9);
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);
        SET_INSTR_ID(out, AD_INSTR_FTSSEL);

        ADD_FIELD(out, Zm);
        ADD_FIELD(out, Zn);
        ADD_FIELD(out, Zd);
        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        concat(DECODE_STR(out), "ftssel %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
        return 0;
      }
    }
    return 1;
  } else
  // op3 11xxxx
  if ( 3 == (op3 >> 4) )
  {
    // SVE Element Count - page 2765
    unsigned op0 = bits(i->opcode, 20, 20);
    unsigned op1 = bits(i->opcode, 11, 13);
    if ( 3 == (op1 >> 1) )
    {
      // SVE saturating inc/dec register by element count - page 2767
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned sf = bits(i->opcode, 20, 20);
      unsigned D = bits(i->opcode, 11, 11);
      unsigned U = bits(i->opcode, 10, 10);
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned idx = (size << 3) | (sf << 2) | (D << 1) | U;
      const struct itab *tab = &satur_tab[idx];
      SET_INSTR_ID(out, tab->instr_id);

      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", tab->instr_s, Rd_s, pattern, imm4);
      return 0;
    } else if ( !op0 && !(op1 >> 1) )
    {
      // SVE saturating inc/dec vector by element count - page 2764
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned D = bits(i->opcode, 11, 11);
      unsigned U = bits(i->opcode, 10, 10);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned idx = (size << 2) | (D << 1) | U;
      const struct itab *tab = &satur_tab2[idx];

      if ( tab->instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, tab->instr_id);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", tab->instr_s, AD_RTBL_Z_128[Zdn], pattern, imm4);
      return 0;
    } else if ( !op0 && (4 == op1) )
    {
      // SVE element count - page 2766
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned op = bits(i->opcode, 10, 10);
      const char *instr_s = NULL;

      if ( op )
        return 1;
      switch(size)
      {
        case 0: instr_s = "cntb";
                SET_INSTR_ID(out, AD_INSTR_CNTB);
         break;
        case 1: instr_s = "cnth";
                SET_INSTR_ID(out, AD_INSTR_CNTH);
         break;
        case 3: instr_s = "cntw";
                SET_INSTR_ID(out, AD_INSTR_CNTW);
         break;
        case 4: instr_s = "cntd";
                SET_INSTR_ID(out, AD_INSTR_CNTD);
         break;
        default: return 1;
      }

      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", instr_s, Rd_s, pattern, imm4);
      return 0;
    } else if ( op0 && !op1 )
    {
      // SVE inc/dec vector by element count - page 2766
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned D = bits(i->opcode, 10, 10);
      int idx = (size << 1) | D;
      const struct itab *tab = &incdec_tab[idx];

      if ( tab->instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, tab->instr_id);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", tab->instr_s, AD_RTBL_Z_128[Zdn], pattern, imm4);
      return 0;
    } else if ( op0 && (4 == op1) )
    {
      // SVE inc/dec register by element count - page 2765
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned D = bits(i->opcode, 10, 10);
      int idx = (size << 1) | D;
      const struct itab *tab = &incdec_tab2[idx];

      if ( tab->instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, tab->instr_id);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Rdn);

      ADD_REG_OPERAND(out, Rdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", tab->instr_s, Rd_s, pattern, imm4);
      return 0;
    }
    return 1;
  }
  return 1;
}

static op00_op11_op20(struct instruction *i, struct ad_insn *out)
{
  unsigned op0 = bits(i->opcode, 22, 23);
  unsigned op1 = bits(i->opcode, 18, 19);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned imm13 = bits(i->opcode, 5, 17);
  unsigned opc = bits(i->opcode, 22, 23);
  const char *instr_s = NULL;

  if ( op1 )
    return 1;
  if ( 3 == op0 )
  {
     SET_INSTR_ID(out, AD_INSTR_DUPM);

     ADD_FIELD(out, imm13);
     ADD_FIELD(out, Zd);
     ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
     ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm13);
     concat(DECODE_STR(out), "dupm %s, #%x", AD_RTBL_Z_128[Zd], imm13);
     return 0;
  }
  // SVE bitwise logical with immediate (unpredicated) - page 2768
  if ( 3 == opc )
    return 1;
  switch(opc)
  {
    case 0: instr_s = "orr";
            SET_INSTR_ID(out, AD_INSTR_ORR);
     break;
    case 1: instr_s = "eor";
            SET_INSTR_ID(out, AD_INSTR_EOR);
     break;
    case 2: instr_s = "and";
            SET_INSTR_ID(out, AD_INSTR_AND);
     break;
    default: return 1;
  }
  ADD_FIELD(out, imm13);
  ADD_FIELD(out, Zd);
  ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm13);
  concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zd], imm13);
  return 0;
}

static op00_op11_op21(struct instruction *i, struct ad_insn *out)
{
  // SVE Integer Wide Immediate - Predicated - page 
  unsigned op0 = bits(i->opcode, 13, 15);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned Pg = bits(i->opcode, 16, 19);
  unsigned size = bits(i->opcode, 22, 23);
  unsigned imm8 = bits(i->opcode, 5, 12);
  int sz = get_sz(size);
  if ( op0 == 6 )
  {
    SET_INSTR_ID(out, AD_INSTR_FCPY);

    ADD_FIELD(out, Pg);
    ADD_FIELD(out, imm8);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
    concat(DECODE_STR(out), "fcpy %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], imm8);
    return 0;
  }
  if ( !(op0 >> 2) )
  {
    unsigned M = bits(i->opcode, 14, 14);
    unsigned sh = bits(i->opcode, 13, 13);

    SET_INSTR_ID(out, AD_INSTR_CPY);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, M);
    ADD_FIELD(out, sh);
    ADD_FIELD(out, imm8);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&sh);

    if ( sh )
     concat(DECODE_STR(out), "cpy %s, %s, #%x, shift", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], imm8);
    else
     concat(DECODE_STR(out), "cpy %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], imm8);
    return 0;
  }
  return 1;
}

static const struct itab unp_tab[] = {
/* 0 0 */ { "sunpklo", AD_INSTR_SUNPKLO },
/* 0 1 */ { "sunpkhi", AD_INSTR_SUNPKHI },
/* 1 0 */ { "uunpklo", AD_INSTR_UUNPKLO },
/* 1 1 */ { "uunpkhi", AD_INSTR_UUNPKHI },
};

static const struct itab zip_tab[] = {
/* 00 0 */ { "zip1", AD_INSTR_ZIP1 },
/* 00 1 */ { "zip2", AD_INSTR_ZIP2 },
/* 01 0 */ { "uzp1", AD_INSTR_UZP1 },
/* 01 1 */ { "uzp2", AD_INSTR_UZP2 },
/* 10 0 */ { "trn1", AD_INSTR_TRN1 },
/* 10 1 */ { "trn2", AD_INSTR_TRN2 },
};

static const struct itab rev_tab[] = {
/* 0 0 */ { "revb", AD_INSTR_REVB },
/* 0 1 */ { "revh", AD_INSTR_REVH },
/* 1 0 */ { "revw", AD_INSTR_REVW },
/* 1 1 */ { "rbit", AD_INSTR_RBIT },
};

static int op00_op11_op25(struct instruction *i, struct ad_insn *out)
{
  unsigned op3 = bits(i->opcode, 10, 15);
  // op3 001xxx
  if ( 1 == (op3 >> 3) )
  {
    // SVE Permute Vector - Unpredicated - page 2769
    unsigned op3 = bits(i->opcode, 10, 12);
    unsigned op2 = bits(i->opcode, 16, 16);
    unsigned op1 = bits(i->opcode, 17, 18);
    unsigned op0 = bits(i->opcode, 19, 20);
    if ( !op3 )
    {
      // dup
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned tsz = bits(i->opcode, 16, 20);
      unsigned imm2 = bits(i->opcode, 22, 23);
      int sz = get_tsz(tsz);

      SET_INSTR_ID(out, AD_INSTR_DUP);
      ADD_FIELD(out, imm2);
      ADD_FIELD(out, tsz);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm2);

      concat(DECODE_STR(out), "dup %s, %s, #%x, shift", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], imm2);
      return 0;
    }
    if ( 4 == op3 )
    {
      // tbl
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);

      SET_INSTR_ID(out, AD_INSTR_TBL);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "tbl %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 1 == (op3 >> 1) )
    {
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned Zm = bits(i->opcode, 16, 20);
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned op = bits(i->opcode, 10, 10);
      const char *instr_s = NULL;

      if ( op )
      {
        instr_s = "tbx";
        SET_INSTR_ID(out, AD_INSTR_TBX);
      } else {
        instr_s = "tbl";
        SET_INSTR_ID(out, AD_INSTR_TBL);
      }
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 6 == op3 )
    {
      if ( !op0 && !op1 && !op2 )
      {
        // dup scalar
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned Rn = bits(i->opcode, 5, 9);
        const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);

        SET_INSTR_ID(out, AD_INSTR_DUP);
        ADD_FIELD(out, Rn);
        ADD_FIELD(out, Zd);

        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
        concat(DECODE_STR(out), "dup %s, %s", AD_RTBL_Z_128[Zd], Rn_s);
        return 0;
      }
      if ( !op0 && (2 == op1) && !op2 )
      {
        // insr
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned Rm = bits(i->opcode, 5, 9);
        const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);

        SET_INSTR_ID(out, AD_INSTR_INSR);
        ADD_FIELD(out, Rm);
        ADD_FIELD(out, Zd);

        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
        concat(DECODE_STR(out), "insr %s, %s", AD_RTBL_Z_128[Zd], Rm_s);
        return 0;
      }
      if ( (2 == op0) && !(op1 >> 1) )
      {
        unsigned Zn = bits(i->opcode, 5, 9);
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);
        unsigned U = bits(i->opcode, 17, 17);
        unsigned H = bits(i->opcode, 16, 16);
        int idx = (U << 1) | H;
        const struct itab *tab = &unp_tab[idx];

        SET_INSTR_ID(out, tab->instr_id);
        ADD_FIELD(out, Zn);
        ADD_FIELD(out, Zd);

        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        concat(DECODE_STR(out), "%s %s, %s", tab->instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
        return 0;
      }
      if ( (2 == op0) && (2 == op1) && !op2 )
      {
        // INSR (SIMD&FP scalar)
        unsigned Zdn = bits(i->opcode, 0, 4);
        unsigned Vm = bits(i->opcode, 5, 9);
        const char *Vm_s = GET_GEN_REG(AD_RTBL_FP_V_128, Vm, NO_PREFER_ZR);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);

        SET_INSTR_ID(out, AD_INSTR_INSR);
        ADD_FIELD(out, Vm);
        ADD_FIELD(out, Zdn);

        ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_REG_OPERAND(out, Vm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
        concat(DECODE_STR(out), "insr %s, %s", AD_RTBL_Z_128[Zdn], Vm_s);
        return 0;
      }
      if ( (3 == op0) && !op1 && !op2 )
      {
        // rev (vector)
        unsigned Zn = bits(i->opcode, 5, 9);
        unsigned Zd = bits(i->opcode, 0, 4);
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);
        SET_INSTR_ID(out, AD_INSTR_REV);
        ADD_FIELD(out, Zn);
        ADD_FIELD(out, Zd);

        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        concat(DECODE_STR(out), "rev %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
        return 0;
      }
      return 1;
    }
    return 1;
  } else
  // op3 010xxx
  if ( 2 == (op3 >> 3) )
  {
    // SVE Permute Predicate - page 2770
    unsigned op3 = bits(i->opcode, 4, 4);
    unsigned op2 = bits(i->opcode, 9, 12);
    unsigned op1 = bits(i->opcode, 16, 20);
    unsigned op0 = bits(i->opcode, 22, 23);
    if ( op3 )
      return 1;
    if ( !(op2 & 1) && !(op1 >> 4) )
    {
      // SVE permute predicate elements - page 2771
      unsigned opc = bits(i->opcode, 11, 12);
      unsigned H = bits(i->opcode, 10, 10);
      if ( 3 == opc )
        return 1;
      else {
        unsigned size = bits(i->opcode, 22, 23);
        int sz = get_sz(size);
        unsigned Pm = bits(i->opcode, 16, 19);
        unsigned Pn = bits(i->opcode, 5, 8);
        unsigned Pd = bits(i->opcode, 0, 3);
        unsigned idx = (opc << 1) | H;
        if ( OOB(idx, zip_tab) )
          return 1;
        ADD_FIELD(out, size);
        ADD_FIELD(out, Pm);
        ADD_FIELD(out, Pn);
        ADD_FIELD(out, Pd);

        ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        ADD_ZREG_OPERAND(out, Pn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        SET_INSTR_ID(out, zip_tab[idx].instr_id);
        concat(DECODE_STR(out), "%s %s, %s, %s", zip_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pn], AD_RTBL_PG_128[Pm]);
        return 0;
      }
    }
    if ( !op0 && (8 == (op1 >> 1)) && !op2 )
    {
      // SVE unpack predicate elements - page 2769
      unsigned Pn = bits(i->opcode, 5, 8);
      unsigned Pd = bits(i->opcode, 0, 3);
      unsigned H = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !H )
      {
        instr_s = "punpklo";
        SET_INSTR_ID(out,AD_INSTR_PUNPKLO);
      } else {
        instr_s = "punpkhi";
        SET_INSTR_ID(out,AD_INSTR_PUNPKHI);
      }
      ADD_FIELD(out, Pn);
      ADD_FIELD(out, Pd);
      ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "%s %s, %s", instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pn]);
      return 0;
    }
    if ( !op2 && (20 == op1) )
    {
      // rev (predicate)
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pn = bits(i->opcode, 5, 8);
      unsigned Pd = bits(i->opcode, 0, 3);

      SET_INSTR_ID(out,AD_INSTR_REV);
      ADD_FIELD(out, Pn);
      ADD_FIELD(out, Pd);
      ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "rev %s, %s", AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pn]);
      return 0;
    }
    return 1;
  } else
  // op3 011xxx
  if ( 3 == (op3 >> 3) )
  {
    // SVE permute vector elements - page 2771
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    unsigned opc = bits(i->opcode, 10, 12);
    if ( OOB(opc, zip_tab) )
      return 1;
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    SET_INSTR_ID(out, zip_tab[opc].instr_id);
    concat(DECODE_STR(out), "%s %s, %s, %s", zip_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  } else
  // op3 10xxxx
  if ( 2 == (op3 >> 4) )
  {
    // SVE Permute Vector - Predicated - page 2770
    unsigned op4 = bits(i->opcode, 13, 13);
    unsigned op3 = bits(i->opcode, 16, 16);
    unsigned op2 = bits(i->opcode, 17, 19);
    unsigned op1 = bits(i->opcode, 20, 20);
    unsigned op0 = bits(i->opcode, 23, 23);
    if ( (1 == op0) && !op1 && !op2 && (1 == op3) && !op4 )
    {
      unsigned size = bits(i->opcode, 22, 22);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);

      SET_INSTR_ID(out, AD_INSTR_COMPACT);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "compact %s %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !op1 && !op2 && !op3 && !op4 )
    {
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Vn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);

      SET_INSTR_ID(out, AD_INSTR_CPY);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Vn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Vn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
      concat(DECODE_STR(out), "cpy %s %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_FP_V_128[Vn]);
      return 0;
    }
    if ( !op1 && !op2 && (1 == op4) )
    {
      // SVE extract element to general register - page 2772
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned M = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !M )
      {
        instr_s = "lasta";
        SET_INSTR_ID(out,AD_INSTR_LASTA);
      } else {
        instr_s = "lastb";
        SET_INSTR_ID(out,AD_INSTR_LASTB);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s %s, %s", instr_s, Rd_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !op1 && (1 == op2) && !op4 )
    {
      // SVE extract element to SIMD&FP scalar register - page 2772
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Vd = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !B )
      {
        instr_s = "lasta";
        SET_INSTR_ID(out,AD_INSTR_LASTA);
      } else {
        instr_s = "lastb";
        SET_INSTR_ID(out,AD_INSTR_LASTB);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Vd);

      ADD_REG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_FP_V_128);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s %s, %s", instr_s, AD_RTBL_FP_V_128[Vd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !op1 && (1 == (op2 >> 1)) && !op4 )
    {
      // SVE reverse within elements - page 2771
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned opc = bits(i->opcode, 16, 17);

      SET_INSTR_ID(out, rev_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s %s, %s", rev_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !op1 && (4 == op2) && !op3 && op4 )
    {
      // cpy (scalar)
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned Rn = bits(i->opcode, 5, 9);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      SET_INSTR_ID(out, AD_INSTR_CPY);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "cpy %s %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], Rn_s);
      return 0;
    }
    if ( !op1 && (4 == op2) && !op4 )
    {
      // SVE conditionally broadcast element to vector - page 2773
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !B )
      {
        instr_s = "clasta";
        SET_INSTR_ID(out,AD_INSTR_LASTA);
      } else {
        instr_s = "clastb";
        SET_INSTR_ID(out,AD_INSTR_LASTB);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( !op1 && (5 == op2) && !op4 )
    {
      // SVE conditionally extract element to SIMD&FP scalar - page 2773
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Vdn = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !B )
      {
        instr_s = "clasta";
        SET_INSTR_ID(out,AD_INSTR_LASTA);
      } else {
        instr_s = "clastb";
        SET_INSTR_ID(out,AD_INSTR_LASTB);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Vdn);

      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Vdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
      concat(DECODE_STR(out), "%s %s %s, %s", instr_s, AD_RTBL_FP_V_128[Vdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( !op1 && (6 == op2) && !op3 && !op4 )
    {
      // SPLICE - Destructive - page 2223
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);

      SET_INSTR_ID(out,AD_INSTR_SPLICE);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "splice %s %s, %s", AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( !op1 && (6 == op2) && op3 && !op4 )
    {
      // SPLICE - Constructive - page 2223
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);

      SET_INSTR_ID(out,AD_INSTR_SPLICE);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "splice %s %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( op1 && !op2 && op4 )
    {
      // SVE conditionally extract element to general register - page 2773
      unsigned size = bits(i->opcode, 22, 23);
      int sz = get_sz(size);
      unsigned Pg = bits(i->opcode, 10, 12);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rdn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      unsigned B = bits(i->opcode, 16, 16);
      const char *instr_s = NULL;
      if ( !B )
      {
        instr_s = "clasta";
        SET_INSTR_ID(out,AD_INSTR_LASTA);
      } else {
        instr_s = "clastb";
        SET_INSTR_ID(out,AD_INSTR_LASTB);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Rdn);

      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s %s, %s", instr_s, Rdn_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  } else
  // op3 11xxxx
  if ( 3 == (op3 >> 4) )
  {
    // sel (vector)
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Pg = bits(i->opcode, 10, 13);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);

    SET_INSTR_ID(out, AD_INSTR_SEL);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "sel %s %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  return 1;
}

static int op00_op12_op25(struct instruction *i, struct ad_insn *out)
{
  unsigned op3 = bits(i->opcode, 10, 15);
  unsigned op0 = bits(i->opcode, 22, 22);
  unsigned imm8h = bits(i->opcode, 16, 20);
  unsigned imm8l = bits(i->opcode, 10, 12);
  unsigned Zm = bits(i->opcode, 5, 9);
  unsigned Zdn = bits(i->opcode, 0, 4);
  unsigned imm = (imm8h << 3) | imm8l;
  if ( op3 >> 3 )
    return 1;
  // SVE Permute Vector - Extract - page 2773
  SET_INSTR_ID(out, AD_INSTR_EXT);
  ADD_FIELD(out, imm8h);
  ADD_FIELD(out, imm8l);
  ADD_FIELD(out, Zm);
  ADD_FIELD(out, Zdn);

  ADD_ZREG_OPERAND(out, Zdn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
  concat(DECODE_STR(out), "ext %s %s, %s, #%x", AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm], imm);
  return 0;
}

static const struct itab zip_tab2[] = {
/* 000 */ { "zip1", AD_INSTR_ZIP1 },
/* 001 */ { "zip2", AD_INSTR_ZIP2 },
/* 010 */ { "uzp1", AD_INSTR_UZP1 },
/* 011 */ { "uzp2", AD_INSTR_UZP2 },
/* 100 */ { NULL, AD_NONE },
/* 101 */ { NULL, AD_NONE },
/* 110 */ { "trn1", AD_INSTR_TRN1 },
/* 111 */ { "trn2", AD_INSTR_TRN2 },
};

static int op00_op13_op25(struct instruction *i, struct ad_insn *out)
{
  unsigned op3 = bits(i->opcode, 10, 15);
  unsigned op = bits(i->opcode, 22, 22);
  if ( op3 >> 3 )
    return 1;
  if ( op )
    return 1;
  else {
    unsigned opc = bits(i->opcode, 10, 12);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    if ( OOB(opc, zip_tab2) )
       return 1;
     ADD_FIELD(out, Zm);
     ADD_FIELD(out, Zn);
     ADD_FIELD(out, Zd);

     ADD_ZREG_OPERAND(out, Zd, _128_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
     ADD_ZREG_OPERAND(out, Zn, _128_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
     ADD_ZREG_OPERAND(out, Zm, _128_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
     SET_INSTR_ID(out, zip_tab2[opc].instr_id);
     concat(DECODE_STR(out), "%s %s, %s, %s", zip_tab2[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
     return 0;
  }
  return 1;
}


static const struct itab cmp_tab[] = {
/* 000 */ { "cmphs", AD_INSTR_CMPHS },
/* 001 */ { "cmphi", AD_INSTR_CMPHI },
/* 010 */ { "cmpeq", AD_INSTR_CMPEQ },
/* 011 */ { "cmpne", AD_INSTR_CMPNE },
/* 100 */ { "cmpge", AD_INSTR_CMPGE },
/* 101 */ { "cmpgt", AD_INSTR_CMPGT },
/* 110 */ { "cmpeq", AD_INSTR_CMPEQ },
/* 111 */ { "cmpne", AD_INSTR_CMPNE },
};

static const struct itab cmp_tab2[] = {
/* 000 */ { "cmpge", AD_INSTR_CMPGE },
/* 001 */ { "cmpgt", AD_INSTR_CMPGT },
/* 010 */ { "cmplt", AD_INSTR_CMPLT },
/* 011 */ { "cmple", AD_INSTR_CMPLE },
/* 100 */ { "cmphs", AD_INSTR_CMPHS },
/* 101 */ { "cmphi", AD_INSTR_CMPHI },
/* 110 */ { "cmplo", AD_INSTR_CMPLO },
/* 111 */ { "cmpls", AD_INSTR_CMPLS },
};

static int op01_op0_op20(struct instruction *i, struct ad_insn *out)
{
  unsigned op0 = bits(i->opcode, 14, 14);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Pd = bits(i->opcode, 0, 3);
  if ( !op0 )
  {
    unsigned op = bits(i->opcode, 15, 15);
    unsigned o2 = bits(i->opcode, 13, 13);
    unsigned ne = bits(i->opcode, 4, 4);
    unsigned idx = (op << 2) | (o2 << 1) | ne;

    SET_INSTR_ID(out, cmp_tab[idx].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Pd);

    ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", cmp_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  } else {
    unsigned U = bits(i->opcode, 15, 15);
    unsigned lt = bits(i->opcode, 13, 13);
    unsigned ne = bits(i->opcode, 4, 4);
    unsigned idx = (U << 2) | (lt << 1) | ne;

    SET_INSTR_ID(out, cmp_tab2[idx].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Pd);

    ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", cmp_tab2[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  return 1;
}

static const struct itab cmp_tab3[] = {
/* 00 */ { "cmphs", AD_INSTR_CMPHS },
/* 01 */ { "cmphi", AD_INSTR_CMPHI },
/* 10 */ { "cmplo", AD_INSTR_CMPLO },
/* 11 */ { "cmpls", AD_INSTR_CMPLS },
};

static int op01_op0_op21(struct instruction *i, struct ad_insn *out)
{
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned imm = bits(i->opcode, 14, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Pd = bits(i->opcode, 0, 3);
  unsigned lt = bits(i->opcode, 13, 13);
  unsigned ne = bits(i->opcode, 4, 4);
  unsigned idx = (lt << 1) | ne;

  SET_INSTR_ID(out, cmp_tab3[idx].instr_id);
  ADD_FIELD(out, size);
  ADD_FIELD(out, imm);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Pd);

  ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);

  concat(DECODE_STR(out), "%s %s, %s, %s, #%x", cmp_tab3[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm);
  return 0;
}

int Disassemble_SVE(struct instruction *i, struct ad_insn *out)
{
    int result = 0;
    // see page 2752 from ISA_A64_xml_futureA-2019-09_OPT.pdf
    unsigned op0 = bits(i->opcode, 29, 31);
    unsigned op1 = bits(i->opcode, 23, 24);
    unsigned op2 = bits(i->opcode, 17, 21);
    unsigned op3 = bits(i->opcode, 10, 15);

    if ( !op0 )
    {
      if ( !(op1 & 2) )
      {
        int op2_hi = op2 & 0x10;
        if ( !op2_hi )
          return op00_op10_op20(i, out);
        else
          return op00_op10_op21(i, out);
      }
      if ( op1 & 2 )
      {
        if ( !(op2 >> 3) )
          return op00_op11_op20(i, out);
        if ( 1 == (op2 >> 3) )
          return op00_op11_op21(i, out);
        if ( 1 == (op2 >> 4) )
          return op00_op11_op25(i, out);
      }
      if ( (op1 == 2) && (1 == (op2 >> 4)) )
        return op00_op12_op25(i, out);
      if ( (op1 == 3) && (1 == (op2 >> 4)) )
        return op00_op13_op25(i, out);
      return 1;
    }

    if ( 1 == op0 )
    {
      if ( !(op2 >> 1) && (0 == (op3 >> 4)) )
        return op01_op0_op20(i, out);
      if ( !(op2 >> 1) && (1 == (op3 >> 4)) )
        return op01_op0_op21(i, out);
    }
    return 1;
}
