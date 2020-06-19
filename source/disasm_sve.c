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

static const struct itab max_min_tab[] = {
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
/* 00 1 0 */ { NULL, AD_NONE },
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

static int op00_op10_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  const char *instr_s = NULL;
  // op3 x1xxxx
  if ( (op3 & 0x10) == 0x10 )
  {
    // SVE Integer Multiply-Add - Predicated
    unsigned op0 = bits(i->opcode, 15, 15);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned op = bits(i->opcode, 13, 13);
    if ( !op0 )
    {
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zda = bits(i->opcode, 0, 4);

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
    unsigned Zm = bits(i->opcode, 5, 9);
    unsigned Zdn = bits(i->opcode, 0, 4);

    // 00x
    if ( !(op0 & 6) )
    {
      unsigned opc = bits(i->opcode, 16, 18);
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
      if ( OOB(opcu, max_min_tab) )
        return 1;
      SET_INSTR_ID(out, max_min_tab[opcu].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", max_min_tab[opcu].instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    // 100 - page 2756
    if ( 4 == op0 )
    {
      unsigned hu = bits(i->opcode, 16, 17);
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
      unsigned ru = bits(i->opcode, 16, 17);
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
      unsigned opc = bits(i->opcode, 16, 18);
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
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Vd = bits(i->opcode, 0, 4);
    if ( !op0 )
    {
      // SVE integer add reduction (predicated)
      unsigned opc = bits(i->opcode, 16, 18);
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
      unsigned opc = bits(i->opcode, 16, 18);
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
      unsigned opc = bits(i->opcode, 16, 18);
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
    // SVE Bitwise Shift - Predicated - page 2758
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned Zdn = bits(i->opcode, 0, 4);
    if ( !(op0 & 2) )
    {
      // SVE bitwise shift by immediate (predicated) - page 2758
      unsigned opc = bits(i->opcode, 16, 19);
      unsigned imm3 = bits(i->opcode, 5, 7);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 8, 9);

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
      // SVE bitwise shift by vector (predicated) - page 2759
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zm = bits(i->opcode, 5, 9);

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
      if ( opc > 3 )
        return 1;
      instr_s = bshift_tab2[opc].instr_s;
      if ( NULL == instr_s )
        return 1;
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

    if ( op0 < 2 )
      return 1;
    if ( op0 == 3 )
    {
      // bitwise unary
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned Zn = bits(i->opcode, 5, 9);
      unsigned Zd = bits(i->opcode, 0, 4);

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

static const struct itab satur_ftab[] = {
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

static const struct itab incdec_ftab[] = {
/* 00 0 */ { "incb", AD_INSTR_INCB },
/* 00 1 */ { "decb", AD_INSTR_DECB },
/* 01 0 */ { "inch", AD_INSTR_INCH },
/* 01 1 */ { "dech", AD_INSTR_DECH },
/* 10 0 */ { "incw", AD_INSTR_INCW },
/* 10 1 */ { "decw", AD_INSTR_DECW },
/* 11 0 */ { "incd", AD_INSTR_INCD },
/* 11 1 */ { "decd", AD_INSTR_DECD },
};

static int op00_op10_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);
  const char *instr_s = NULL;
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  // op3 000xxx
  if ( !(op3 >> 3) )
  {
    // SVE integer add/subtract vectors (unpredicated) 
    unsigned opc = bits(i->opcode, 10, 12);
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
      ADD_FIELD(out, size);
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
      unsigned Zk = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned o2 = bits(i->opcode, 10, 10);
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
    instr_s = "index";
    SET_INSTR_ID(out, AD_INSTR_SMAX);
    if ( 0 == op0 )
    {
      unsigned imm5 = bits(i->opcode, 5, 9);
      unsigned imm5b = bits(i->opcode, 16, 20);

      ADD_FIELD(out, size);
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
      if ( R )
      {
        instr_s = "sqrdmulh";
        SET_INSTR_ID(out, AD_INSTR_SQRDMULH);
      } else {
        instr_s = "sqdmulh";
        SET_INSTR_ID(out, AD_INSTR_SQDMULH);
      }
      ADD_FIELD(out, size);
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
      ADD_FIELD(out, size);
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
      ADD_FIELD(out, size);
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
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 19, 20);
      size = (tszh << 2) | tszl;
      sz = get_sz(size);

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
      ADD_FIELD(out, size);
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
      // SVE constructive prefix (unpredicated) - page 2765
      unsigned opc = bits(i->opcode, 22, 23);
      unsigned opc2 = bits(i->opcode, 16, 20);
      if ( opc )
        return 1;
      if ( opc2 )
        return 1;
      else {
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
      // SVE floating-point exponential accelerator - page 2764
      unsigned opc = bits(i->opcode, 16, 20);
      if ( opc )
        return 1;
      else {
        SET_INSTR_ID(out, AD_INSTR_FEXPA);

        ADD_FIELD(out, size);
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
        SET_INSTR_ID(out, AD_INSTR_FTSSEL);

        ADD_FIELD(out, size);
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
      unsigned sf = bits(i->opcode, 20, 20);
      unsigned D = bits(i->opcode, 11, 11);
      unsigned U = bits(i->opcode, 10, 10);
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned idx = (size << 3) | (sf << 2) | (D << 1) | U;
      SET_INSTR_ID(out, satur_ftab[idx].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Rd);

      ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", satur_ftab[idx].instr_s, Rd_s, pattern, imm4);
      return 0;
    } else if ( !op0 && !(op1 >> 1) )
    {
      // SVE saturating inc/dec vector by element count - page 2764
      unsigned D = bits(i->opcode, 11, 11);
      unsigned U = bits(i->opcode, 10, 10);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned idx = (size << 2) | (D << 1) | U;

      if ( satur_tab2[idx].instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, satur_tab2[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", satur_tab2[idx].instr_s, AD_RTBL_Z_128[Zdn], pattern, imm4);
      return 0;
    } else if ( !op0 && (4 == op1) )
    {
      // SVE element count - page 2766
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned op = bits(i->opcode, 10, 10);

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

      ADD_FIELD(out, size);
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
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned D = bits(i->opcode, 10, 10);
      int idx = (size << 1) | D;

      if ( incdec_tab[idx].instr_s == NULL )
        return 1;
      SET_INSTR_ID(out, incdec_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", incdec_tab[idx].instr_s, AD_RTBL_Z_128[Zdn], pattern, imm4);
      return 0;
    } else if ( op0 && (4 == op1) )
    {
      // SVE inc/dec register by element count - page 2765
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned imm4 = bits(i->opcode, 16, 19);
      unsigned D = bits(i->opcode, 10, 10);
      int idx = (size << 1) | D;

      SET_INSTR_ID(out, incdec_ftab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Rdn);

      ADD_REG_OPERAND(out, Rdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, #%x, mul #%x", incdec_ftab[idx].instr_s, Rd_s, pattern, imm4);
      return 0;
    }
    return 1;
  }
  return 1;
}

static op00_op11_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
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

static op00_op11_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
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

    ADD_FIELD(out, size);
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
    ADD_FIELD(out, size);
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

static const struct itab rev_ftab[] = {
/* 0 0 */ { "revb", AD_INSTR_REVB },
/* 0 1 */ { "revh", AD_INSTR_REVH },
/* 1 0 */ { "revw", AD_INSTR_REVW },
/* 1 1 */ { "rbit", AD_INSTR_RBIT },
};

static int op00_op11_op25(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  const char *instr_s = NULL;
  // op3 001xxx
  if ( 1 == (op3 >> 3) )
  {
    // SVE Permute Vector - Unpredicated - page 2769
    unsigned op3 = bits(i->opcode, 10, 12);
    unsigned op2 = bits(i->opcode, 16, 16);
    unsigned op1 = bits(i->opcode, 17, 18);
    unsigned op0 = bits(i->opcode, 19, 20);

    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    if ( !op3 )
    {
      // dup
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
      SET_INSTR_ID(out, AD_INSTR_TBL);
      ADD_FIELD(out, size);
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
      unsigned op = bits(i->opcode, 10, 10);
      if ( op )
      {
        instr_s = "tbx";
        SET_INSTR_ID(out, AD_INSTR_TBX);
      } else {
        instr_s = "tbl";
        SET_INSTR_ID(out, AD_INSTR_TBL);
      }
      ADD_FIELD(out, size);
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
      unsigned Zd = bits(i->opcode, 0, 4);
      if ( !op0 && !op1 && !op2 )
      {
        // dup scalar
        unsigned Rn = bits(i->opcode, 5, 9);
        const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

        SET_INSTR_ID(out, AD_INSTR_DUP);
        ADD_FIELD(out, size);
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
        unsigned Rm = bits(i->opcode, 5, 9);
        const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

        SET_INSTR_ID(out, AD_INSTR_INSR);
        ADD_FIELD(out, size);
        ADD_FIELD(out, Rm);
        ADD_FIELD(out, Zd);

        ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
        ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
        concat(DECODE_STR(out), "insr %s, %s", AD_RTBL_Z_128[Zd], Rm_s);
        return 0;
      }
      if ( (2 == op0) && !(op1 >> 1) )
      {
        unsigned U = bits(i->opcode, 17, 17);
        unsigned H = bits(i->opcode, 16, 16);
        int idx = (U << 1) | H;
        const struct itab *tab = &unp_tab[idx];

        SET_INSTR_ID(out, tab->instr_id);
        ADD_FIELD(out, size);
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

        SET_INSTR_ID(out, AD_INSTR_INSR);
        ADD_FIELD(out, size);
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
        SET_INSTR_ID(out, AD_INSTR_REV);
        ADD_FIELD(out, size);
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

        SET_INSTR_ID(out, zip_tab[idx].instr_id);
        ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        ADD_ZREG_OPERAND(out, Pn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
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
      unsigned Pn = bits(i->opcode, 5, 8);
      unsigned Pd = bits(i->opcode, 0, 3);

      SET_INSTR_ID(out,AD_INSTR_REV);
      ADD_FIELD(out, size);
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
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    unsigned opc = bits(i->opcode, 10, 12);
    if ( OOB(opc, zip_tab) )
      return 1;
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    SET_INSTR_ID(out, zip_tab[opc].instr_id);
    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
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

    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    if ( (1 == op0) && !op1 && !op2 && (1 == op3) && !op4 )
    {
      // compact - page 1486
      unsigned size = bits(i->opcode, 22, 22);
      int sz = get_sz(size);

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
      // cpy - page 1494
      unsigned Vn = bits(i->opcode, 5, 9);

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
      unsigned Rd = bits(i->opcode, 0, 4);
      const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);
      unsigned M = bits(i->opcode, 16, 16);
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
      unsigned Vd = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
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
      unsigned opc = bits(i->opcode, 16, 17);

      SET_INSTR_ID(out, rev_ftab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s %s, %s", rev_ftab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !op1 && (4 == op2) && !op3 && op4 )
    {
      // cpy (scalar)
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
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
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
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Vdn = bits(i->opcode, 0, 4);
      unsigned B = bits(i->opcode, 16, 16);
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
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rdn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      unsigned B = bits(i->opcode, 16, 16);
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

static int op00_op12_op25(struct instruction *i, struct ad_insn *out, unsigned op3)
{
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

static int op00_op13_op25(struct instruction *i, struct ad_insn *out, unsigned op3)
{
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

static int op01_op0_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
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

static int op01_op0_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
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

static const struct itab cmp_tab4[] = {
/* 000 */ { "cmpge", AD_INSTR_CMPGE },
/* 001 */ { "cmpgt", AD_INSTR_CMPGT },
/* 010 */ { "cmplt", AD_INSTR_CMPLT },
/* 011 */ { "cmple", AD_INSTR_CMPLE },
/* 100 */ { "cmpeq", AD_INSTR_CMPEQ },
/* 101 */ { "cmpne", AD_INSTR_CMPNE },
};

static int op1_op1_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned imm = bits(i->opcode, 16, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned op = bits(i->opcode, 15, 15);
  unsigned o2 = bits(i->opcode, 13, 13);
  unsigned ne = bits(i->opcode, 4, 4);
  unsigned Pd = bits(i->opcode, 0, 3);
  int idx = (op << 2) | (o2 << 1) | ne;
  if ( (op3 >> 4) & 1 )
    return 1;
  // SVE integer compare with signed immediate - page 2775
  if ( OOB(idx, cmp_tab4) )
    return 1;

  SET_INSTR_ID(out, cmp_tab4[idx].instr_id);
  ADD_FIELD(out, size);
  ADD_FIELD(out, imm);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Pd);

  ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);

  concat(DECODE_STR(out), "%s %s, %s, %s, #%x", cmp_tab4[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm);
  return 0;
}

static const struct itab logbit_tab[] = {
/* 0 0 0 0 */ { "and", AD_INSTR_AND },
/* 0 0 0 1 */ { "bic", AD_INSTR_BIC },
/* 0 0 1 0 */ { "eor", AD_INSTR_EOR },
/* 0 0 1 1 */ { "sel", AD_INSTR_SEL },
/* 0 1 0 0 */ { "and", AD_INSTR_AND },
/* 0 1 0 1 */ { "bic", AD_INSTR_BIC },
/* 0 1 1 0 */ { "eor", AD_INSTR_EOR },
/* 0 1 1 1 */ { NULL, AD_NONE },
/* 1 0 0 0 */ { "orr", AD_INSTR_ORR },
/* 1 0 0 1 */ { "orn", AD_INSTR_ORN },
/* 1 0 1 0 */ { "nor", AD_INSTR_NOR },
/* 1 0 1 1 */ { "nand", AD_INSTR_NAND },
/* 1 1 0 0 */ { "orr", AD_INSTR_ORR },
/* 1 1 0 1 */ { "orn", AD_INSTR_ORN },
/* 1 1 1 0 */ { "nor", AD_INSTR_NOR },
/* 1 1 1 1 */ { "nand", AD_INSTR_NAND },
};

static const struct itab brk_tab[] = {
/* 00 */ { "brkpa", AD_INSTR_BRKPA },
/* 01 */ { "brkpb", AD_INSTR_BRKPB },
/* 10 */ { "brkpas", AD_INSTR_BRKPAS },
/* 11 */ { "brkpbs", AD_INSTR_BRKPBS },
};

static const struct itab brk_tab2[] = {
/* 00 */ { "brka", AD_INSTR_BRKA },
/* 01 */ { "brkas", AD_INSTR_BRKAS },
/* 10 */ { "brkb", AD_INSTR_BRKB },
/* 11 */ { "brkbs", AD_INSTR_BRKBS },
};

static int op1_op1_op30(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  if ( 1 == (op3 >> 4) )
  {
    // SVE predicate logical operations - page 2775
    unsigned op = bits(i->opcode, 23, 23);
    unsigned S = bits(i->opcode, 22, 22);
    unsigned o2 = bits(i->opcode, 9, 9);
    unsigned o3 = bits(i->opcode, 4, 4);
    unsigned Pm = bits(i->opcode, 16, 19);
    unsigned Pg = bits(i->opcode, 10, 13);
    unsigned Pn = bits(i->opcode, 5, 8);
    unsigned Pd = bits(i->opcode, 0, 3);
    int idx = (op << 3) | (S << 2) | (o2 << 1) | o3;
    if ( OOB(idx, logbit_tab) )
      return 1;
    if ( logbit_tab[idx].instr_s == NULL )
      return 1;
    SET_INSTR_ID(out, logbit_tab[idx].instr_id);
    ADD_FIELD(out, Pm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Pn);
    ADD_FIELD(out, Pd);

    ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);

    concat(DECODE_STR(out), "%s %s, %s, %s, %s", logbit_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn], AD_RTBL_PG_128[Pm]);
    return 0;
  }
  if ( 3 == (op3 >> 4) )
  {
    // SVE Propagate Break - page 2776
    unsigned op0 = bits(i->opcode, 9, 9);
    if ( op0 )
      return 1;
    else {
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      unsigned B = bits(i->opcode, 4, 4);
      unsigned Pm = bits(i->opcode, 16, 19);
      unsigned Pg = bits(i->opcode, 10, 13);
      unsigned Pn = bits(i->opcode, 5, 8);
      unsigned Pd = bits(i->opcode, 0, 3);
      unsigned idx = (S << 1) | B;
      if ( op )
        return 1;
      SET_INSTR_ID(out, brk_tab[idx].instr_id);
      ADD_FIELD(out, Pm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Pn);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", brk_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn], AD_RTBL_PG_128[Pm]);
      return 0;
    }
  }
  return 1;
}

static int op1_op1_op31(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  // 1 1 1xxxx
  if ( 1 == (op3 >> 4) )
  {
    // SVE Partition Break - page 2776
    unsigned op0 = bits(i->opcode, 23, 23);
    unsigned op1 = bits(i->opcode, 16, 19);
    unsigned op2 = bits(i->opcode, 9, 9);
    unsigned op4 = bits(i->opcode, 4, 4);
    unsigned S = bits(i->opcode, 22, 22);
    unsigned Pg = bits(i->opcode, 10, 13);
    unsigned Pn = bits(i->opcode, 5, 8);
    unsigned Pd = bits(i->opcode, 0, 3);
    if ( !op1 && !op2 )
    {
      // SVE partition break condition - page 2777
      unsigned B = bits(i->opcode, 23, 23);
      unsigned M = bits(i->opcode, 4, 4);
      unsigned idx = (B << 0) | S;
      if ( S && M )
        return 1;
      SET_INSTR_ID(out, brk_tab2[idx].instr_id);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Pn);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);

      concat(DECODE_STR(out), "%s %s, %s, %s", brk_tab2[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn]);
      return 0;
    }
    if ( !op0 && (8 == op1) && !op2 && !op3 )
    {
      // SVE propagate break to next partition - page 2777
      const char *instr_s = NULL;
      if ( !S )
      {
        instr_s = "brkn";
        SET_INSTR_ID(out, AD_INSTR_BRKN);
      } else {
        instr_s = "brkns";
        SET_INSTR_ID(out, AD_INSTR_BRKNS);
      }
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Pn);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);

      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn], AD_RTBL_PG_128[Pd]);
      return 0;
    }
    return 1;
  }
  // 1 1 11xxxx
  if ( 3 == (op3 >> 4) )
  {
    // SVE Predicate Misc - page 2777
    unsigned op0 = bits(i->opcode, 16, 19);
    unsigned op1 = bits(i->opcode, 11, 13);
    unsigned op2 = bits(i->opcode, 9, 10);
    unsigned op3 = bits(i->opcode, 5, 8);
    unsigned op4 = bits(i->opcode, 4, 4);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    if ( op4 )
      return 1;
    if ( !op0 && !(op2 & 1) )
    {
      // SVE predicate test - page 2778
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      unsigned opc2 = bits(i->opcode, 0, 3);
      if ( op )
        return 1;
      if ( !S )
        return 1;
      if ( opc2 )
        return 1;
      else {
       unsigned Pg = bits(i->opcode, 10, 13);
       unsigned Pn = bits(i->opcode, 5, 8);

       SET_INSTR_ID(out, AD_INSTR_PTEST);
       ADD_FIELD(out, Pg);
       ADD_FIELD(out, Pn);

       ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
       ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
       concat(DECODE_STR(out), "ptest %s, %s", AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn]);
       return 0;
      }
      return 1;
    }
    if ( (8 == op0) && !op1 && !op2 )
    {
      // SVE predicate first active - page 2778
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      if ( op )
        return 1;
      if ( !S )
        return 1;
      else {
       unsigned Pg = bits(i->opcode, 5, 8);
       unsigned Pdn = bits(i->opcode, 0, 3);
       SET_INSTR_ID(out, AD_INSTR_PFIRST);
       ADD_FIELD(out, Pg);
       ADD_FIELD(out, Pdn);

       ADD_ZREG_OPERAND(out, Pdn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
       ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
       concat(DECODE_STR(out), "pfirst %s, %s", AD_RTBL_PG_128[Pdn], AD_RTBL_PG_128[Pg]);
       return 0;
      }
      return 1;
    }
    if ( (8 == op0) && (4 == op1) && (2 == op2) && !op3 )
    {
      // SVE predicate zero - page 2777
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      if ( op )
        return 1;
      if ( S )
        return 1;
      else {
        unsigned Pd = bits(i->opcode, 0, 3);
        SET_INSTR_ID(out, AD_INSTR_PFALSE);
        ADD_FIELD(out, Pd);

        ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        concat(DECODE_STR(out), "pfalse %s", AD_RTBL_PG_128[Pd]);
        return 0;
      }
      return 1;
    }
    if ( (8 == op0) && (6 == op1) && !op2 )
    {
      // SVE predicate read from FFR (predicate) - page 2779
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      unsigned Pg = bits(i->opcode, 5, 8);
      unsigned Pd = bits(i->opcode, 0, 3);
      if ( op )
        return 1;
      else {
        const char *instr_s = NULL;
        if ( !S )
        {
          instr_s = "rdffr";
          SET_INSTR_ID(out, AD_INSTR_RDFFR);
        } else {
          instr_s = "rdffrs";
          SET_INSTR_ID(out, AD_INSTR_RDFFRS);
        }
        ADD_FIELD(out, Pg);
        ADD_FIELD(out, Pd);

        ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        concat(DECODE_STR(out), "%s %s, %s", instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg]);
        return 0;
      }
      return 1;
    }
    if ( (9 == op0) && !op1 && (2 == op2) )
    {
      unsigned Pg = bits(i->opcode, 5, 8);
      unsigned Pdn = bits(i->opcode, 0, 3);
      SET_INSTR_ID(out, AD_INSTR_PNEXT);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Pdn);

      ADD_ZREG_OPERAND(out, Pdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "pnext %s, %s", AD_RTBL_PG_128[Pdn], AD_RTBL_PG_128[Pg]);
      return 0;
    }
    if ( (9 == op0) && (6 == op1) && !op2 && !op3 )
    {
      // SVE predicate read from FFR (unpredicated) - page 2779
      unsigned op = bits(i->opcode, 23, 23);
      unsigned S = bits(i->opcode, 22, 22);
      if ( op )
        return 1;
      if ( S )
        return 1;
      else {
        unsigned Pd = bits(i->opcode, 0, 3);
        SET_INSTR_ID(out, AD_INSTR_RDFFR);
        ADD_FIELD(out, Pd);

        ADD_ZREG_OPERAND(out, Pd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
        concat(DECODE_STR(out), "rdffr %s", AD_RTBL_PG_128[Pd]);
        return 0;
      }
      return 1;
    }
    if ( (4 == (op0 >> 1)) && (4 == op1) && !(op2 >> 1) )
    {
      // SVE predicate initialize - page
      unsigned S = bits(i->opcode, 16, 16);
      unsigned pattern = bits(i->opcode, 5, 9);
      unsigned Pd = bits(i->opcode, 0, 3);
      const char *instr_s = NULL;
      if ( !S )
      {
        instr_s = "ptrue";
        SET_INSTR_ID(out, AD_INSTR_PTRUE);
      } else {
        instr_s = "ptrues";
        SET_INSTR_ID(out, AD_INSTR_PTRUES);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, pattern);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&pattern);
      concat(DECODE_STR(out), "%s %s, #%x", instr_s, AD_RTBL_PG_128[Pd], pattern);
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab while_ftab[] = {
/* 0 0 0 */ { "whilege", AD_INSTR_WHILEGE },
/* 0 0 1 */ { "whilegt", AD_INSTR_WHILEGT },
/* 0 1 0 */ { "whilelt", AD_INSTR_WHILELT },
/* 0 1 1 */ { "whilele", AD_INSTR_WHILELE },
/* 1 0 0 */ { "whilehs", AD_INSTR_WHILEHS },
/* 1 0 1 */ { "whilehi", AD_INSTR_WHILEHI },
/* 1 1 0 */ { "whilelo", AD_INSTR_WHILELO },
/* 1 1 1 */ { "whilels", AD_INSTR_WHILELS },
};

static const struct itab addsub_tab[] = {
/* 0 0 0 */ { "add", AD_INSTR_ADD },
/* 0 0 1 */ { "sub", AD_INSTR_SUB },
/* 0 1 0 */ { NULL, AD_NONE },
/* 0 1 1 */ { "subr", AD_INSTR_SUBR },
/* 1 0 0 */ { "sqadd", AD_INSTR_SQADD },
/* 1 0 1 */ { "uqadd", AD_INSTR_UQADD },
/* 1 1 0 */ { "sqsub", AD_INSTR_SQSUB },
/* 1 1 1 */ { "uqsub", AD_INSTR_SQSUB },
};


static int op1_op1_op41(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  if ( 1 == (op3 >> 4) )
    return 1;
  if ( !(op3 >> 4) )
  {
    //  SVE Integer Compare - Scalars - page 2779
    unsigned op0 = bits(i->opcode, 12, 13);
    unsigned op1 = bits(i->opcode, 10, 11);
    unsigned op2 = bits(i->opcode, 0, 3);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned Rn = bits(i->opcode, 5, 9);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Pd = bits(i->opcode, 0, 3);
    if ( !(op0 >> 1) )
    {
      // SVE integer compare scalar count and limit - page 2780
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
      unsigned U = bits(i->opcode, 11, 11);
      unsigned lt = bits(i->opcode, 10, 10);
      unsigned eq = bits(i->opcode, 4, 4);
      int idx = (U << 2) | (lt << 1) | eq;

      SET_INSTR_ID(out, while_ftab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));

      concat(DECODE_STR(out), "%s %s, %s, %s", while_ftab[idx].instr_s, AD_RTBL_PG_128[Pd], Rn_s, Rm_s);
      return 0;
    }
    if ( op1 )
      return 1;
    if ( (2 == op0) && !op2 )
    {
      // SVE conditionally terminate scalars - page 2780
      unsigned op = bits(i->opcode, 23, 23);
      unsigned ne = bits(i->opcode, 4, 4);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
      const char *instr_s = NULL;
      if ( !op )
        return 1;
      if ( !ne )
      {
        instr_s = "ctermeq";
        SET_INSTR_ID(out, AD_INSTR_CTERMEQ);
      } else {
        instr_s = "ctermne";
        SET_INSTR_ID(out, AD_INSTR_CTERMNE);
      }
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Rn);

      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));

      concat(DECODE_STR(out), "%s %s, %s", instr_s, Rn_s, Rm_s);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE pointer conflict compare - page 2780
      unsigned rw = bits(i->opcode, 4, 4);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
      const char *instr_s = NULL;
      if ( !rw )
      {
        instr_s = "whilewr";
        SET_INSTR_ID(out, AD_INSTR_WHILEWR);
      } else {
        instr_s = "whilerw";
        SET_INSTR_ID(out, AD_INSTR_WHILERW);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Pd);

      ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));

      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pd], Rn_s, Rm_s);
      return 0;
    }
    return 1;
  }
  if ( 3 == (op3 >> 4) )
  {
    // SVE Integer Wide Immediate - Unpredicated - page 2779
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned op1 = bits(i->opcode, 16, 16);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Zdn = bits(i->opcode, 0, 4);
    if ( !op0 )
    {
      // SVE integer add/subtract immediate (unpredicated) - page 2781
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned imm8 = bits(i->opcode, 5, 12);
      if ( NULL == addsub_tab[opc].instr_s )
        return 1;
      SET_INSTR_ID(out, addsub_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm8);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
      concat(DECODE_STR(out), "%s %s, %s, #%x", addsub_tab[opc].instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], imm8);
      return 0;
    }
    if ( 1 == op0 )
    {
      // SVE integer min/max immediate (unpredicated) - page 2781
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned imm8 = bits(i->opcode, 5, 12);
      unsigned o2 = bits(i->opcode, 13, 13);
      if ( o2 )
        return 1;
      if ( opc > 4 )
        return 1;
      if ( OOB(opc, max_min_tab) )
        return 1;
      SET_INSTR_ID(out, max_min_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm8);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
      concat(DECODE_STR(out), "%s %s, %s, #%x", max_min_tab[opc].instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], imm8);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE integer multiply immediate (unpredicated) - page 2780
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned imm8 = bits(i->opcode, 5, 12);
      unsigned o2 = bits(i->opcode, 13, 13);
      if ( o2 )
        return 1;
      if ( opc )
        return 1;

      SET_INSTR_ID(out, AD_INSTR_MUL);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm8);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
      concat(DECODE_STR(out), "mul %s, %s, #%x", AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], imm8);
      return 0;
    }
    if ( 3 == op0 && !op1 )
    {
      // SVE broadcast integer immediate (unpredicated) - page 2782
      unsigned opc = bits(i->opcode, 17, 18);
      unsigned imm8 = bits(i->opcode, 5, 12);

      if ( opc )
        return 1;

      SET_INSTR_ID(out, AD_INSTR_DUP);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm8);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
      concat(DECODE_STR(out), "dup %s, #%x", AD_RTBL_Z_128[Zdn], imm8);
      return 0;
    }
    if ( 3 == op0 && op1 )
    {
      unsigned opc = bits(i->opcode, 17, 18);
      unsigned imm8 = bits(i->opcode, 5, 12);
      unsigned Zd = bits(i->opcode, 0, 4);
      unsigned o2 = bits(i->opcode, 13, 13);

      if ( o2 )
        return 1;
      if ( opc )
        return 1;

      SET_INSTR_ID(out, AD_INSTR_FDUP);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm8);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm8);
      concat(DECODE_STR(out), "fdup %s, #%x", AD_RTBL_Z_128[Zd], imm8);
      return 0;
    }
    return 1;
  }
  return 1;
}

static int op1_op1_op42(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned opc = bits(i->opcode, 16, 18);
  unsigned o2 = bits(i->opcode, 9, 9);
  if ( 2 != (op3 >> 4) )
    return 1;
  // SVE predicate count - page 2782
  if ( o2 )
    return 1;
  if ( opc )
    return 1;
  else {
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Pg = bits(i->opcode, 10, 13);
    unsigned Pn = bits(i->opcode, 5, 8);
    unsigned Rd = bits(i->opcode, 0, 4);
    const char *Rd_s = GET_GEN_REG(AD_RTBL_GEN_64, Rd, NO_PREFER_ZR);

    SET_INSTR_ID(out, AD_INSTR_CNTP);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Pn);
    ADD_FIELD(out, Rd);

    ADD_REG_OPERAND(out, Rd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    concat(DECODE_STR(out), "cntp %s, %s, %s", Rd_s, AD_RTBL_PG_128[Pg], AD_RTBL_PG_128[Pn]);
    return 0;
  }
  return 1;
}

static const struct itab incdec_tab3[] = {
/* 0 0 */ { "sqincp", AD_INSTR_SQINCP },
/* 0 1 */ { "uqincp", AD_INSTR_UQINCP },
/* 1 0 */ { "sqdecp", AD_INSTR_SQDECP },
/* 1 1 */ { "uqdecp", AD_INSTR_UQDECP },
};

static const struct itab incdec_tab4[] = {
/* 0 0 0 */ { "sqincp", AD_INSTR_SQINCP },
/* 0 0 1 */ { "sqincp", AD_INSTR_SQINCP },
/* 0 1 0 */ { "uqincp", AD_INSTR_UQINCP },
/* 0 1 1 */ { "uqincp", AD_INSTR_UQINCP },
/* 1 0 0 */ { "sqdecp", AD_INSTR_SQDECP },
/* 1 0 1 */ { "sqdecp", AD_INSTR_SQDECP },
/* 1 1 0 */ { "uqdecp", AD_INSTR_UQDECP },
/* 1 1 1 */ { "uqdecp", AD_INSTR_UQDECP },
};

static int op1_op1_op52(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  if ( 5 == (op3 >> 3) )
    return 1;
  if ( 8 == (op3 >> 2) )
  {
    // SVE Inc/Dec by Predicate Count - page 2782
    unsigned op0 = bits(i->opcode, 18, 18);
    unsigned op1 = bits(i->opcode, 11, 11);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned D = bits(i->opcode, 17, 17);
    unsigned U = bits(i->opcode, 16, 16);
    unsigned Pm = bits(i->opcode, 5, 8);
    unsigned Zdn = bits(i->opcode, 0, 4);
    const char *instr_s = NULL;
    if ( !op0 && !op1 )
    {
      // SVE saturating inc/dec vector by predicate count - page 2783
      unsigned opc = bits(i->opcode, 9, 10);
      unsigned idx = (D << 1) | U;
      if ( opc )
        return 1;
      SET_INSTR_ID(out, incdec_tab3[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "%s %s, %s", incdec_tab3[idx].instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pm]);
      return 0;
    }
    if ( !op0 && op1 )
    {
      // SVE saturating inc/dec register by predicate count - page 2783
      unsigned op = bits(i->opcode, 9, 9);
      unsigned sf = bits(i->opcode, 10, 10);
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rdn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      unsigned idx = (D << 2) | (U << 1) | sf;
      if ( op )
        return 1;
      SET_INSTR_ID(out, incdec_tab4[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pm);
      ADD_FIELD(out, Rdn);

      ADD_REG_OPERAND(out, Rdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "%s %s, %s", incdec_tab4[idx].instr_s, Rdn_s, AD_RTBL_PG_128[Pm]);
      return 0;
    }
    if ( op0 && !op1 )
    {
      // SVE inc/dec vector by predicate count - page 2783
      unsigned op = bits(i->opcode, 17, 17);
      unsigned D = bits(i->opcode, 16, 16);
      unsigned opc2 = bits(i->opcode, 9, 10);
      if ( op || opc2 )
        return 1;
      if ( !D )
      {
        instr_s = "incp";
        SET_INSTR_ID(out, AD_INSTR_INCP);
      } else {
        instr_s = "decp";
        SET_INSTR_ID(out, AD_INSTR_DECP);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "%s %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pm]);
      return 0;
    }
    if ( op0 && op1 )
    {
      // SVE inc/dec register by predicate count - page 
      unsigned op = bits(i->opcode, 17, 17);
      unsigned D = bits(i->opcode, 16, 16);
      unsigned opc2 = bits(i->opcode, 9, 10);
      unsigned Rdn = bits(i->opcode, 0, 4);
      const char *Rdn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rdn, NO_PREFER_ZR);
      if ( op || opc2 )
        return 1;
      if ( !D )
      {
        instr_s = "incp";
        SET_INSTR_ID(out, AD_INSTR_INCP);
      } else {
        instr_s = "decp";
        SET_INSTR_ID(out, AD_INSTR_DECP);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pm);
      ADD_FIELD(out, Rdn);

      ADD_REG_OPERAND(out, Rdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Pm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "%s %s, %s", instr_s, Rdn_s, AD_RTBL_PG_128[Pm]);
      return 0;
    }
    return 1;
  }
  if ( 9 == (op3 >> 2) )
  {
    // SVE Write FFR - page 2784
    unsigned op0 = bits(i->opcode, 18, 18);
    unsigned op1 = bits(i->opcode, 16, 17);
    unsigned op2 = bits(i->opcode, 9, 11);
    unsigned op3 = bits(i->opcode, 5, 8);
    unsigned op4 = bits(i->opcode, 0, 4);
    if ( op4 || op2 || op1 )
      return 1;
    if ( !op0 )
    {
      unsigned opc = bits(i->opcode, 22, 23);
      unsigned Pn = bits(i->opcode, 5, 8);
      if ( opc )
        return 1;
      SET_INSTR_ID(out, AD_INSTR_WRFFR);
      ADD_FIELD(out, Pn);
      ADD_ZREG_OPERAND(out, Pn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      concat(DECODE_STR(out), "wrffr %s", AD_RTBL_PG_128[Pn]);
      return 0;
    }
    if ( op0 && !op3 )
    {
      unsigned opc = bits(i->opcode, 22, 23);
      if ( opc )
        return 1;
      SET_INSTR_ID(out, AD_INSTR_SETFFR);
      concat(DECODE_STR(out), "setffr");
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab sqdml_tab[] = {
/* 0 0 */ { "sqdmlalb", AD_INSTR_SQDMLALB },
/* 0 1 */ { "sqdmlalt", AD_INSTR_SQDMLALT },
/* 1 0 */ { "sqdmlslb", AD_INSTR_SQDMLSLB },
/* 1 1 */ { "sqdmlslt", AD_INSTR_SQDMLSLT },
};

static const struct itab sml_tab[] = {
/* 0 0 0 */ { "smlalb", AD_INSTR_SMLALB },
/* 0 0 1 */ { "smlalt", AD_INSTR_SMLALT },
/* 0 1 0 */ { "umlalb", AD_INSTR_UMLALB },
/* 0 1 1 */ { "umlalt", AD_INSTR_UMLALT },
/* 1 0 0 */ { "smlslb", AD_INSTR_SMLSLB },
/* 1 0 1 */ { "smlslt", AD_INSTR_SMLSLT },
/* 1 1 0 */ { "umlslb", AD_INSTR_UMLSLB },
/* 1 1 1 */ { "umlslt", AD_INSTR_UMLSLT },
};

static const struct itab smul_tab[] = {
/* 0 0 */ { "smullb", AD_INSTR_SMULLB },
/* 0 1 */ { "smullt", AD_INSTR_SMULLT },
/* 1 0 */ { "umullb", AD_INSTR_UMULLB },
/* 1 1 */ { "umullt", AD_INSTR_UMULLT },
};

static int op02_op0_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  // SVE Multiply - Indexed - page 2789
  unsigned op0 = bits(i->opcode, 10, 15);
  unsigned size = bits(i->opcode, 22, 23);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zda = bits(i->opcode, 0, 4);
  int sz = get_sz(size);
  const char *instr_s = NULL;

  if ( 0x3f == op0 )
    return 1;

  if ( 0 == (op0 >> 1) )
  {
    // SVE integer dot product (indexed) - page 2789
    unsigned U = bits(i->opcode, 10, 10);
    unsigned Zm = 0;
    if ( size == 2 )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( size == 3 )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;
    if ( !U )
    {
      instr_s = "sdot";
      SET_INSTR_ID(out, AD_INSTR_SDOT);
    } else {
      instr_s = "udot";
      SET_INSTR_ID(out, AD_INSTR_UDOT);
    }
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }

  if ( 1 == (op0 >> 1) )
  {
    // SVE2 integer multiply-add (indexed) - page 2790
    unsigned S = bits(i->opcode, 10, 10);
    unsigned Zm = 0;
    if ( !(size & 2) )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 2 == size )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    if ( !S )
    {
      instr_s = "mla";
      SET_INSTR_ID(out, AD_INSTR_MLA);
    } else {
      instr_s = "mls";
      SET_INSTR_ID(out, AD_INSTR_MLS);
    }

    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }

  if ( 2 == (op0 >> 1) )
  {
    // SVE2 saturating multiply-add high (indexed) - page 2790
    unsigned S = bits(i->opcode, 10, 10);
    unsigned Zm = 0;
    if ( !(size & 2) )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 2 == size )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    if ( !S )
    {
      instr_s = "sqrdmlah";
      SET_INSTR_ID(out, AD_INSTR_SQRDMLAH);
    } else {
      instr_s = "sqrdmlsh";
      SET_INSTR_ID(out, AD_INSTR_SQRDMLSH);
    }

    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }

  if ( 3 == (op0 >> 1) )
  {
    // SVE mixed sign dot product (indexed) - page 2790
    unsigned U = bits(i->opcode, 10, 10);
    unsigned imm2 = bits(i->opcode, 19, 20);
    unsigned Zm = bits(i->opcode, 16, 18);
    if ( 2 != size )
      return 1;
    if ( !U )
    {
      instr_s = "usdot";
      SET_INSTR_ID(out, AD_INSTR_USDOT);
    } else {
      instr_s = "sudot";
      SET_INSTR_ID(out, AD_INSTR_SUDOT);
    }
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm2);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm2);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm2);
    return 0;
  }

  if ( 1 == (op0 >> 3) )
  {
    // SVE2 saturating multiply-add (indexed) - page 2789
    unsigned S = bits(i->opcode, 12, 12);
    unsigned T = bits(i->opcode, 10, 10);
    unsigned Zm = bits(i->opcode, 16, 19);
    unsigned imm = 0;
    int idx = (S << 1) | T;
    if ( size < 2 )
      return 1;
    if ( size == 3 )
    {
      unsigned i3h = bits(i->opcode, 19, 20);
      unsigned i3l = bits(i->opcode, 11, 11);
      imm = (i3h << 1) | i3l;
    } else if ( size == 4 )
    {
      unsigned i2h = bits(i->opcode, 20, 20);
      unsigned i2l = bits(i->opcode, 11, 11);
      imm = (i2h << 1) | i2l;
    } else
      return 1;

    instr_s = sqdml_tab[idx].instr_s;
    SET_INSTR_ID(out, sqdml_tab[idx].instr_id);

    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  if ( 4 == (op0 >> 2) )
  {
    // SVE2 complex integer dot product (indexed) - page 2791
    unsigned Zm = 0;
    unsigned rot = bits(i->opcode, 10, 11);
    instr_s = "cdot";
    SET_INSTR_ID(out, AD_INSTR_CDOT);
    if ( 2 == size )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, rot);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
    concat(DECODE_STR(out), "cdot %s, %s, %s, #%x", AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], rot);
    return 0;
  }

  if ( 5 == (op0 >> 2) )
    return 1;

  if ( 6 == (op0 >> 2) )
  {
    // SVE2 complex integer multiply-add (indexed) - page 2791
    unsigned Zm = 0;
    unsigned rot = bits(i->opcode, 10, 11);
    instr_s = "cmla";
    SET_INSTR_ID(out, AD_INSTR_CMLA);
    if ( 2 == size )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, rot);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
    concat(DECODE_STR(out), "cmla %s, %s, %s, #%x", AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], rot);
    return 0;
  }

  if ( 7 == (op0 >> 2) )
  {
    // SVE2 complex saturating multiply-add (indexed) - page 2790
    unsigned Zm = 0;
    unsigned rot = bits(i->opcode, 10, 11);
    instr_s = "sqrdcmlah";
    SET_INSTR_ID(out, AD_INSTR_SQRDCMLAH);
    if ( 2 == size )
    {
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, rot);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
    concat(DECODE_STR(out), "sqrdcmlah %s, %s, %s, #%x", AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], rot);
    return 0;
  }

  if ( 2 == (op0 >> 4) )
  {
    // SVE2 integer multiply-add long (indexed) - page 2792
    unsigned Zm = 0;
    unsigned imm = bits(i->opcode, 11, 11);
    unsigned S = bits(i->opcode, 13, 13);
    unsigned U = bits(i->opcode, 12, 12);
    unsigned T = bits(i->opcode, 10, 10);
    int idx = (S << 2) | (U << 1) | T;
    if ( OOB(idx, sml_tab) )
      return 1;
    if ( 2 == size )
    {
      unsigned i3h = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
      imm |= (i3h << 1);
    } else if ( 3 == size )
    {
      unsigned i2h = bits(i->opcode, 20, 20);
      Zm = bits(i->opcode, 16, 19);
      imm |= (i2h << 1);
    } else
      return 1;

    SET_INSTR_ID(out, sml_tab[idx].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", sml_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  if ( 6 == (op0 >> 3) )
  {
    // SVE2 integer multiply long (indexed) - page 2792
    unsigned Zm = 0;
    unsigned U = bits(i->opcode, 12, 12);
    unsigned T = bits(i->opcode, 10, 10);
    unsigned imm = bits(i->opcode, 11, 11);
    int idx = (U << 1) | T;

    if ( OOB(idx, smul_tab) )
      return 1;

    if ( 2 == size )
    {
      unsigned i3h = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
      imm |= (i3h << 1);
    } else if ( 3 == size )
    {
      unsigned i2h = bits(i->opcode, 20, 20);
      Zm = bits(i->opcode, 16, 19);
      imm |= (i2h << 1);
    } else
      return 1;

    SET_INSTR_ID(out, smul_tab[idx].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", smul_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  if ( 14 == (op0 >> 2) )
  {
    // SVE2 saturating multiply (indexed) - page 2792
    unsigned T = bits(i->opcode, 10, 10);
    unsigned Zm = 0;
    unsigned imm = bits(i->opcode, 11, 11);

    if ( 2 == size )
    {
      unsigned i3h = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
      imm |= (i3h << 1);
    } else if ( 3 == size )
    {
      unsigned i2h = bits(i->opcode, 20, 20);
      Zm = bits(i->opcode, 16, 19);
      imm |= (i2h << 1);
    } else
      return 1;

    if ( !T )
    {
      instr_s = "sqdmullb";
      SET_INSTR_ID(out, AD_INSTR_SQDMULLB);
    } else {
      instr_s = "sqdmullt";
      SET_INSTR_ID(out, AD_INSTR_SQDMULLT);
    }
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  if ( 30 == (op0 >> 1) )
  {
    // SVE2 saturating multiply high (indexed) - page 2793
    unsigned Zm = bits(i->opcode, 16, 18);
    unsigned imm = 0;
    unsigned R = bits(i->opcode, 10, 10);

    if ( size < 2 )
    {
      unsigned imm3l = bits(i->opcode, 19, 20);
      imm = bits(i->opcode, 22, 22);
      imm = (imm << 2) | imm3l;
    } else if ( 2 == size )
    {
      imm = bits(i->opcode, 19, 20);
    } else if ( 3 == size )
    {
      imm = bits(i->opcode, 20, 20);
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    if ( !R )
    {
      instr_s = "sqdmulh";
      SET_INSTR_ID(out, AD_INSTR_SQDMULH);
    } else {
      instr_s = "sqrdmulh";
      SET_INSTR_ID(out, AD_INSTR_SQRDMULH);
    }
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  if ( 62 == op0 )
  {
    // SVE2 integer multiply (indexed) - page 2793
    unsigned Zm = bits(i->opcode, 16, 18);
    unsigned imm = 0;

    if ( size < 2 )
    {
      unsigned imm3l = bits(i->opcode, 19, 20);
      imm = bits(i->opcode, 22, 22);
      imm = (imm << 2) | imm3l;
    } else if ( 2 == size )
    {
      imm = bits(i->opcode, 19, 20);
    } else if ( 3 == size )
    {
      imm = bits(i->opcode, 20, 20);
      Zm = bits(i->opcode, 16, 19);
    } else
      return 1;

    instr_s = "mul";
    SET_INSTR_ID(out, AD_INSTR_MUL);
    ADD_FIELD(out, size);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zda);

    ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }

  return 1;
}

static const struct itab iunop_tab[] = {
/* 0 0 */ { "urecpe", AD_INSTR_URECPE },
/* 0 1 */ { "ursqrte", AD_INSTR_URSQRTE },
/* 1 0 */ { "sqabs", AD_INSTR_SQABS },
/* 1 1 */ { "sqneg", AD_INSTR_SQNEG },
};

static const struct itab shl_tab[] = {
/* 0 0 0 0 */ { NULL, AD_NONE },
/* 0 0 0 1 */ { NULL, AD_NONE },
/* 0 0 1 0 */ { "srshl", AD_INSTR_SRSHL },
/* 0 0 1 1 */ { "urshl", AD_INSTR_URSHL },
/* 0 1 0 0 */ { NULL, AD_NONE },
/* 0 1 0 1 */ { NULL, AD_NONE },
/* 0 1 1 0 */ { "srshlr", AD_INSTR_SRSHLR },
/* 0 1 1 1 */ { "urshlr", AD_INSTR_URSHLR },
/* 1 0 0 0 */ { NULL, AD_NONE },
/* 1 0 0 1 */ { NULL, AD_NONE },
/* 1 0 1 0 */ { "sqrshl", AD_INSTR_SQRSHL },
/* 1 0 1 1 */ { "uqrshl", AD_INSTR_UQRSHL },
/* 1 1 0 0 */ { "sqshlr", AD_INSTR_SQSHLR },
/* 1 1 0 1 */ { "uqshlr", AD_INSTR_UQSHLR },
/* 1 1 1 0 */ { "sqrshlr", AD_INSTR_SQRSHLR },
/* 1 1 1 1 */ { "uqrshlr", AD_INSTR_UQRSHLR },
};

static const struct itab addsub_tab2[] = {
/* 0 0 0 */ { "shadd", AD_INSTR_SHADD },
/* 0 0 1 */ { "uhadd", AD_INSTR_UHADD },
/* 0 1 0 */ { "shsub", AD_INSTR_SHSUB },
/* 0 1 1 */ { "uhsub", AD_INSTR_UHSUB },
/* 1 0 0 */ { "srhadd", AD_INSTR_SRHADD },
/* 1 0 1 */ { "urhadd", AD_INSTR_URHADD },
/* 1 1 0 */ { "shsubr", AD_INSTR_SHSUBR },
/* 1 1 1 */ { "uhsubr", AD_INSTR_UHSUBR },
};

static const struct itab addsub_tab3[] = {
/* 0 0 0 */ { "sqadd", AD_INSTR_SQADD },
/* 0 0 1 */ { "uqadd", AD_INSTR_UQADD },
/* 0 1 0 */ { "sqsub", AD_INSTR_SQSUB },
/* 0 1 1 */ { "uqsub", AD_INSTR_UQSUB },
/* 1 0 0 */ { "suqadd", AD_INSTR_SUQADD },
/* 1 0 1 */ { "usqadd", AD_INSTR_USQADD },
/* 1 1 0 */ { "sqsubr", AD_INSTR_SQSUBR },
/* 1 1 1 */ { "uqsubr", AD_INSTR_UQSUBR },
};

static const struct itab max_min2[] = {
/* 00 U0 */ { NULL, AD_NONE },
/* 00 U1 */ { "addp", AD_INSTR_ADDP },
/* 01 U0 */ { NULL, AD_NONE },
/* 01 U1 */ { NULL, AD_NONE },
/* 10 U0 */ { "smaxp", AD_INSTR_SMAXP },
/* 10 U1 */ { "umaxp", AD_INSTR_UMAXP },
/* 11 U0 */ { "sminp", AD_INSTR_SMINP },
/* 11 U1 */ { "uminp", AD_INSTR_UMINP },
};

static int op02_op0_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  if ( !(op3 >> 5) )
  {
    // SVE Integer Multiply-Add - Unpredicated - page 2785
    unsigned op0 = bits(i->opcode, 10, 14);
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zda = bits(i->opcode, 0, 4);
    const char *instr_s = NULL;
    if ( !(op0 >> 1) )
    {
      // SVE integer dot product (unpredicated)
      unsigned U = bits(i->opcode, 10, 10);
      if ( !U )
      {
        instr_s = "sdot";
        SET_INSTR_ID(out, AD_INSTR_SDOT);
      } else {
        instr_s = "udot";
        SET_INSTR_ID(out, AD_INSTR_UDOT);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 1 == (op0 >> 1) )
    {
      // SVE2 saturating multiply-add interleaved long - page 2785
      unsigned S = bits(i->opcode, 10, 10);
      if ( !S )
      {
        instr_s = "sqdmlalbt";
        SET_INSTR_ID(out, AD_INSTR_SQDMLALBT);
      } else {
        instr_s = "sqdmlslbt";
        SET_INSTR_ID(out, AD_INSTR_SQDMLSLBT);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 1 == (op0 >> 2) )
    {
      // CDOT (vectors) - page 1439
      unsigned rot = bits(i->opcode, 10, 11);
      SET_INSTR_ID(out, AD_INSTR_CDOT);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, rot);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
      concat(DECODE_STR(out), "cdot %s %s, %s, #%x", AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], rot);
      return 0;
    }
    if ( 1 == (op0 >> 3) )
    {
      // SVE2 complex integer multiply-add - page 2784
      unsigned rot = bits(i->opcode, 10, 11);
      unsigned op = bits(i->opcode, 12, 12);
      if ( !op )
      {
        instr_s = "cmla";
        SET_INSTR_ID(out, AD_INSTR_CMLA);
      } else {
        instr_s = "sqrdcmlah";
        SET_INSTR_ID(out, AD_INSTR_SQRDCMLAH);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, rot);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
      concat(DECODE_STR(out), "%s %s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], rot);
      return 0;
    }
    if ( 2 == (op0 >> 3) )
    {
      // SVE2 integer multiply-add long - page 2786
      unsigned S = bits(i->opcode, 12, 12);
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      int idx = (S << 2) | (U << 1) | T;
      if ( OOB(idx, sml_tab) )
        return 1;

      SET_INSTR_ID(out, sml_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", sml_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 6 == (op0 >> 2) )
    {
      // SVE2 saturating multiply-add long - page 2786
      unsigned S = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      int idx = (S << 1) | T;
      instr_s = sqdml_tab[idx].instr_s;
      SET_INSTR_ID(out, sqdml_tab[idx].instr_id);

      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 30 == op0 )
    {
      // SVE mixed sign dot product - page 2786
      if ( size != 2 )
        return 1;
      SET_INSTR_ID(out, AD_INSTR_USDOT);
      // no size here?
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);
      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "usdot %s, %s, %s", AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  }
  if ( 2 == (op3 >> 4) )
  {
    // SVE2 Integer - Predicated - page 2787
    unsigned op0 = bits(i->opcode, 17, 20);
    unsigned op1 = bits(i->opcode, 13, 13);

    unsigned size = bits(i->opcode, 22, 23);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zda = bits(i->opcode, 0, 4);
    unsigned Pg = bits(i->opcode, 10, 12);
    int sz = get_sz(size);
    const char *instr_s = NULL;
    if ( 2 == op0 && op1 )
    {
      // SVE2 integer pairwise add and accumulate long - page 2787
      unsigned U = bits(i->opcode, 16, 16);
      if ( !U )
      {
        instr_s = "sadalp";
        SET_INSTR_ID(out, AD_INSTR_SADALP);
      } else {
        instr_s = "uadalp";
        SET_INSTR_ID(out, AD_INSTR_UADALP);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !(op0 & 0xa) && op1 )
    {
      // SVE2 integer unary operations (predicated) - page 2787
      unsigned Q = bits(i->opcode, 19, 19);
      unsigned opc = bits(i->opcode, 16, 17);
      int idx;
      if ( opc & 2 )
        return 1;
      idx = (Q << 1) | opc;
      if ( OOB(idx, iunop_tab) )
        return 1;
      SET_INSTR_ID(out, iunop_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", iunop_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !(op0 >> 3) && !op1 )
    {
      // SVE2 saturating/rounding bitwise shift left (predicated) - page 2787
      unsigned Q = bits(i->opcode, 19, 19);
      unsigned R = bits(i->opcode, 18, 18);
      unsigned N = bits(i->opcode, 17, 17);
      unsigned U = bits(i->opcode, 16, 16);
      int idx = (Q << 3) | (R << 2) | (N << 1) | U;
      if ( OOB(idx, shl_tab) )
        return 1;
      if ( NULL == shl_tab[idx].instr_s )
        return 1;

      SET_INSTR_ID(out, shl_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", shl_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 2 == (op0 >> 2) && !op1 )
    {
      // SVE2 integer halving add/subtract (predicated) - page 2788
      // seems that somebody wait for RSU actions, he-he
      unsigned R = bits(i->opcode, 18, 18);
      unsigned S = bits(i->opcode, 17, 17);
      unsigned U = bits(i->opcode, 16, 16);
      int idx = (R << 2) | (S << 1) | U;

      if ( OOB(idx, addsub_tab2) )
        return 1;
      SET_INSTR_ID(out, addsub_tab2[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", addsub_tab2[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 2 == (op0 >> 2) && op1 )
    {
      // SVE2 integer pairwise arithmetic - page 2788
      unsigned opc = bits(i->opcode, 17, 18);
      unsigned U = bits(i->opcode, 16, 16);
      unsigned idx = (opc << 1 ) | U;

      if ( OOB(idx, max_min2) )
        return 1;
      if ( NULL == max_min2[idx].instr_s )
        return 1;

      SET_INSTR_ID(out, max_min2[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", max_min2[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 3 == (op0 >> 2) && !op1 )
    {
      // SVE2 saturating add/subtract - page 2789
      unsigned op = bits(i->opcode, 18, 18);
      unsigned S = bits(i->opcode, 17, 17);
      unsigned U = bits(i->opcode, 16, 16);
      int idx = (op << 2) | (S << 1) | U;
      if ( OOB(idx, addsub_tab3) )
        return 1;
      SET_INSTR_ID(out, addsub_tab3[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", addsub_tab3[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab sab_tab[] = {
/* 0 0 */ { "sabalb", AD_INSTR_SABALB },
/* 0 1 */ { "sabalt", AD_INSTR_SABALT },
/* 1 0 */ { "uabalb", AD_INSTR_UABALB },
/* 1 1 */ { "uabalt", AD_INSTR_UABALT },
};

static const struct itab adc_tab[] = {
/* 0 0 */ { "adclb", AD_INSTR_ADCLB },
/* 0 1 */ { "adclt", AD_INSTR_ADCLT },
/* 1 0 */ { "sbclb", AD_INSTR_SBCLB },
/* 1 1 */ { "sbclt", AD_INSTR_SBCLT },
};

static const struct itab sra_tab[] = {
/* 0 0 */ { "ssra", AD_INSTR_SSRA },
/* 0 1 */ { "usra", AD_INSTR_USRA },
/* 1 0 */ { "srsra", AD_INSTR_SRSRA },
/* 1 1 */ { "ursra", AD_INSTR_URSRA },
};

static const struct itab shl_tab2[] = {
/* 0 0 */ { "sshllb", AD_INSTR_SSHLLB },
/* 0 1 */ { "sshllt", AD_INSTR_SSHLLT },
/* 1 0 */ { "ushllb", AD_INSTR_USHLLB },
/* 1 1 */ { "ushllt", AD_INSTR_USHLLT },
};

static const struct itab lbt_tab[] = {
/* 0 0 */ { "saddlbt", AD_INSTR_SADDLBT },
/* 0 1 */ { NULL, AD_NONE },
/* 1 0 */ { "ssublbt", AD_INSTR_SSUBLBT },
/* 1 1 */ { "ssubltb", AD_INSTR_SSUBLTB },
};

static const struct itab mla_tab[] = {
/* 0 0 */ { "smmla", AD_INSTR_SMMLA },
/* 0 1 */ { NULL, AD_NONE },
/* 1 0 */ { "usmmla", AD_INSTR_USMMLA },
/* 1 1 */ { "ummla", AD_INSTR_UMMLA },
};

static const struct itab bitperm_tab[] = {
/* 0 0 */ { "bext", AD_INSTR_BEXT },
/* 0 1 */ { "bdep", AD_INSTR_BDEP },
/* 1 0 */ { "bgrp", AD_INSTR_BGRP },
/* 1 1 */ { NULL, AD_NONE },
};

static const struct itab sad_tab[] = {
/* 00 0 0 */ { "saddlb", AD_INSTR_SADDLB },
/* 00 0 1 */ { "saddlt", AD_INSTR_SADDLT },
/* 00 0 1 */ { "uaddlb", AD_INSTR_UADDLB },
/* 00 1 1 */ { "uaddlt", AD_INSTR_UADDLT },
/* 01 0 0 */ { "ssublb", AD_INSTR_SSUBLB },
/* 01 0 1 */ { "ssublt", AD_INSTR_SSUBLT },
/* 01 1 0 */ { "usublb", AD_INSTR_USUBLB },
/* 01 1 1 */ { "usublt", AD_INSTR_USUBLT },
/* 10 0 0 */ { NULL, AD_NONE },
/* 10 0 1 */ { NULL, AD_NONE },
/* 10 1 0 */ { NULL, AD_NONE },
/* 10 1 1 */ { NULL, AD_NONE },
/* 11 0 0 */ { "sabdlb", AD_INSTR_SABDLB },
/* 11 0 1 */ { "sabdlt", AD_INSTR_SABDLT },
/* 11 1 0 */ { "uabdlb", AD_INSTR_UABDLB },
/* 11 1 1 */ { "uabdlt", AD_INSTR_UABDLT },
};

static const struct itab wbt_tab[] = {
/* 0 0 0 */ { "saddwb", AD_INSTR_SADDWB },
/* 0 0 1 */ { "saddwt", AD_INSTR_SADDWT },
/* 0 1 0 */ { "uaddwb", AD_INSTR_UADDWB },
/* 0 1 1 */ { "uaddwt", AD_INSTR_UADDWT },
/* 1 0 0 */ { "ssubwb", AD_INSTR_SSUBWB },
/* 1 0 1 */ { "ssubwt", AD_INSTR_SSUBWT },
/* 1 1 0 */ { "usubwb", AD_INSTR_USUBWB },
/* 1 1 1 */ { "usubwt", AD_INSTR_USUBWT },
};

static const struct itab mul_tab[] = {
/* 0 0 0 */ { "sqdmullb", AD_INSTR_SQDMULLB },
/* 0 0 1 */ { "sqdmullt", AD_INSTR_SQDMULLT },
/* 0 1 0 */ { "pmullb", AD_INSTR_PMULLB },
/* 0 1 1 */ { "pmullt", AD_INSTR_PMULLT },
/* 1 0 0 */ { "smullb", AD_INSTR_SMULLB },
/* 1 0 1 */ { "smullt", AD_INSTR_SMULLT },
/* 1 1 0 */ { "umullb", AD_INSTR_UMULLB },
/* 1 1 1 */ { "umullt", AD_INSTR_UMULLT },
};

static int op02_op1_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  const char *instr_s = NULL;
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);

  if ( !(op3 >> 5) )
  {
    // SVE2 Widening Integer Arithmetic - page 2793
    unsigned op0 = bits(i->opcode, 13, 14);

    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    if ( !(op0 >> 1) )
    {
      // CVE2 integer add/subtract long - page 2793
      unsigned op = bits(i->opcode, 13, 13);
      unsigned S = bits(i->opcode, 12, 12);
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = (op << 3) | (S << 2) | (U << 1) | T;
      if ( NULL == sad_tab[idx].instr_s )
        return 1;

      SET_INSTR_ID(out, sad_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", sad_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE2 integer add/subtract wide - page 2794
      unsigned S = bits(i->opcode, 12, 12);
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = (S << 2) | (U << 1) | T;

      SET_INSTR_ID(out, wbt_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", wbt_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE2 integer multiply long - page 2794
      unsigned op = bits(i->opcode, 12, 12);
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = (op << 2) | (U << 1) | T;

      if ( OOB(idx, mul_tab) )
        return 1;
      SET_INSTR_ID(out, mul_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", mul_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  }
  if ( 2 == (op3 >> 4) )
  {
    // SVE Misc - page 2795
    unsigned op0 = bits(i->opcode, 23, 23);
    unsigned op1 = bits(i->opcode, 10, 13);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zd = bits(i->opcode, 0, 4);
    unsigned Zm = bits(i->opcode, 16, 20);

    if ( !op0 && (2 == (op1 >> 2)) )
    {
      // SVE2 bitwise shift left long - page 2795
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned tszh = bits(i->opcode, 22, 22);
      unsigned tszl = bits(i->opcode, 19, 20);
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned tsz = (tszh << 2) | tszl;
      int idx = (U << 1) | T;
      int sz = get_tsz(tsz);

      SET_INSTR_ID(out, shl_tab2[idx].instr_id);
      ADD_FIELD(out, tsz);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "%s %s, %s, #%x", shl_tab2[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], imm3);
      return 0;
    }
    if ( !(op1 >> 2) )
    {
      // SVE2 integer add/subtract interleaved long - page 2795
      unsigned S = bits(i->opcode, 11, 11);
      unsigned tb = bits(i->opcode, 10, 10);
      unsigned idx = (S << 1) | tb;

      if ( NULL == lbt_tab[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, lbt_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", lbt_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 2 == (op1 >> 1) )
    {
      // SVE2 bitwise exclusive-or interleaved - page 2795
      unsigned tb = bits(i->opcode, 10, 10);

      if ( !tb )
      {
        instr_s = "eorbt";
        SET_INSTR_ID(out, AD_INSTR_EORBT);
      } else {
        instr_s = "eortb";
        SET_INSTR_ID(out, AD_INSTR_EORTB);
      }

      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 6 == op1 )
    {
      // SVE integer matrix multiply accumulate - page 2796
      unsigned idx = bits(i->opcode, 22, 23);
      if ( NULL == mla_tab[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, mla_tab[idx].instr_id);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", mla_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 3 == (op1 >> 2) )
    {
      // SVE2 bitwise permute - page 2796
      unsigned opc = bits(i->opcode, 10, 11);

      if ( NULL == bitperm_tab[opc].instr_s )
        return 1;
      SET_INSTR_ID(out, bitperm_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", bitperm_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  }
  if ( 3 == (op3 >> 4) )
  {
    // SVE2 Accumulate - page 2796
    unsigned op0 = bits(i->opcode, 17, 20);
    unsigned op1 = bits(i->opcode, 11, 13);
    unsigned Zm = bits(i->opcode, 16, 20);
    unsigned Zn = bits(i->opcode, 5, 9);
    unsigned Zda = bits(i->opcode, 0, 4);

    if ( 3 == op1 )
    {
      // SVE2 complex integer add - page 2796
      unsigned op = bits(i->opcode, 16, 16);
      unsigned rot = bits(i->opcode, 10, 10);
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned Zdn = bits(i->opcode, 0, 4);
      if ( op0 )
        return 1;
      if ( !op )
      {
        instr_s = "cadd";
        SET_INSTR_ID(out, AD_INSTR_CADD);
      } else {
        instr_s = "sqcadd";
        SET_INSTR_ID(out, AD_INSTR_SQCADD);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, rot);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
      concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm], rot);
      return 0;
    }
    if ( !(op1 >> 1) )
    {
      // SVE2 integer absolute difference and accumulate long - page 2797
      unsigned U = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      int idx = (U << 1) | T;

      SET_INSTR_ID(out, sab_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", sab_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 2 == op1 )
    {
      // SVE2 integer add/subtract long with carry - page 2797
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = ((size & 2) << 1) | T;
      
      SET_INSTR_ID(out, adc_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", adc_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( 2 == (op1 >> 1) )
    {
      // SVE2 bitwise shift right and accumulate - page 2797
      unsigned R = bits(i->opcode, 11, 11);
      unsigned U = bits(i->opcode, 10, 10);
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 19, 20);
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned tsz = (tszh << 2) | tszl;
      int idx = (R << 1) | U;

      sz = get_tsz(tsz);
      SET_INSTR_ID(out, sra_tab[idx].instr_id);
      ADD_FIELD(out, tsz);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "%s %s, %s, #%x", sra_tab[idx].instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], imm3);
      return 0;
    }
    if ( 6 == op1 )
    {
      // SVE2 bitwise shift and insert - page 2797
      unsigned tszh = bits(i->opcode, 22, 23);
      unsigned tszl = bits(i->opcode, 19, 20);
      unsigned imm3 = bits(i->opcode, 16, 18);
      unsigned op = bits(i->opcode, 10, 10);
      unsigned tsz = (tszh << 2) | tszl;
      
      if ( !op )
      {
        instr_s = "sri"; // yep
        SET_INSTR_ID(out, AD_INSTR_SRI);
      } else {
        instr_s = "sli"; // and spi
        SET_INSTR_ID(out, AD_INSTR_SLI);
      }

      ADD_FIELD(out, tsz);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "%s %s, %s, #%x", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], imm3);
      return 0;
    }
    if ( 7 == op1 )
    {
      // SVE2 integer absolute difference and accumulate - page 2798
      unsigned U = bits(i->opcode, 10, 10);

      if ( !U )
      {
        instr_s = "saba"; // small sabaka
        SET_INSTR_ID(out, AD_INSTR_SABA);
      } else {
        instr_s = "uaba";
        SET_INSTR_ID(out, AD_INSTR_UABA);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zda);

      ADD_ZREG_OPERAND(out, Zda, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zda], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab aes_tab[] = {
/* 0 0 */ { "aese", AD_INSTR_AESE },
/* 0 1 */ { "aesd", AD_INSTR_AESD },
/* 1 0 */ { "sm4e", AD_INSTR_SM4E },
/* 1 1 */ { NULL, AD_NONE },
};

static const struct itab hnb_ftab[] = {
/* 0 0 0 */ { "addhnb", AD_INSTR_ADDHNB },
/* 0 0 1 */ { "addhnt", AD_INSTR_ADDHNT },
/* 0 1 0 */ { "raddhnb", AD_INSTR_RADDHNB },
/* 0 1 1 */ { "raddhnt", AD_INSTR_RADDHNT },
/* 1 0 0 */ { "subhnb", AD_INSTR_SUBHNB },
/* 1 0 1 */ { "subhnt", AD_INSTR_SUBHNT },
/* 1 1 0 */ { "rsubhnb", AD_INSTR_RSUBHNB },
/* 1 1 1 */ { "rsubhnt", AD_INSTR_RSUBHNT },
};

static const struct itab tnt_tab[] = {
/* 0 0 0 */ { "sqxtnb", AD_INSTR_SQXTNB },
/* 0 0 1 */ { "sqxtnt", AD_INSTR_SQXTNT },
/* 0 1 0 */ { "uqxtnb", AD_INSTR_UQXTNB },
/* 0 1 1 */ { "uqxtnt", AD_INSTR_UQXTNT },
/* 1 0 0 */ { "sqxtunb", AD_INSTR_SQXTUNB },
/* 1 0 1 */ { "sqxtunt", AD_INSTR_SQXTUNT },
};

static const struct itab urt_tab[] = {
/* 0 0 0 0 */ { "sqshrunb", AD_INSTR_SQSHRUNB },
/* 0 0 0 1 */ { "sqshrunt", AD_INSTR_SQSHRUNT },
/* 0 0 0 1 */ { "sqrshrunb", AD_INSTR_SQRSHRUNB },
/* 0 0 1 1 */ { "sqrshrunt", AD_INSTR_SQRSHRUNT },
/* 0 1 0 0 */ { "shrnb", AD_INSTR_SHRNB },
/* 0 1 0 1 */ { "shrnt", AD_INSTR_SHRNT },
/* 0 1 1 0 */ { "rshrnb", AD_INSTR_RSHRNB },
/* 0 1 1 1 */ { "rshrnt", AD_INSTR_RSHRNT },
/* 1 0 0 0 */ { "sqshrnb", AD_INSTR_SQSHRNB },
/* 1 0 0 1 */ { "sqshrnt", AD_INSTR_SQSHRNT },
/* 1 0 1 0 */ { "sqrshrnb", AD_INSTR_SQRSHRNB },
/* 1 0 1 1 */ { "sqrshrnt", AD_INSTR_SQRSHRNT },
/* 1 1 0 0 */ { "uqshrnb", AD_INSTR_UQSHRNB },
/* 1 1 0 1 */ { "uqshrnt", AD_INSTR_UQSHRNT },
/* 1 1 1 0 */ { "uqrshrnb", AD_INSTR_UQRSHRNB },
/* 1 1 1 1 */ { "uqrshrnt", AD_INSTR_UQRSHRNT },
};

static int op02_op1_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  const char *instr_s = NULL;
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned tszh = bits(i->opcode, 22, 22);
  unsigned tszl = bits(i->opcode, 19, 20);

  if ( !(op3 >> 5) )
  {
    // SVE2 Narrowing - page 2798
    unsigned op0 = bits(i->opcode, 23, 23);
    unsigned op1 = bits(i->opcode, 16, 18);
    unsigned op2 = bits(i->opcode, 13, 14);
    if ( 3 == op2 )
    {
      // SVE2 integer add/subtract narrow high part - page 2799
      unsigned S = bits(i->opcode, 12, 12);
      unsigned R = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = (S << 2) | (R << 1) | T;

      SET_INSTR_ID(out, hnb_ftab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", hnb_ftab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( op0 )
      return 1;
    if ( !op1 && (2 == op2) )
    {
      // SVE2 saturating extract narrow - page 2798
      unsigned T = bits(i->opcode, 10, 10);
      unsigned opc = bits(i->opcode, 11, 12);
      unsigned tsz = (tszh << 2) | tszl;
      unsigned idx = (opc << 1) | T;
      sz = get_tsz(tsz);

      if ( OOB(idx, tnt_tab) )
        return 1;
      SET_INSTR_ID(out, tnt_tab[idx].instr_id);
      ADD_FIELD(out, tsz);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s", tnt_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( !(op2 >> 1) )
    {
      // SVE2 bitwise shift right narrow - page 2798
      unsigned tsz = (tszh << 2) | tszl;
      unsigned op = bits(i->opcode, 13, 13);
      unsigned imm3 = bits(i->opcode, 16, 18);
      // urt - urinotherapy ?
      unsigned U = bits(i->opcode, 12, 12);
      unsigned R = bits(i->opcode, 11, 11);
      unsigned T = bits(i->opcode, 10, 10);
      unsigned idx = (op << 3) | (U << 2) | (R << 1) | T;
      sz = get_tsz(tsz);

      if ( OOB(idx, urt_tab) )
        return 1;
      SET_INSTR_ID(out, urt_tab[idx].instr_id);
      ADD_FIELD(out, tsz);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "%s %s, %s, #%x", urt_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], imm3);
      return 0;
    }
    return 1;
  }
  if ( 4 == (op3 >> 3) )
  {
    // SVE2 character match - page 2799
    unsigned Pg = bits(i->opcode, 10, 12);
    unsigned Pd = bits(i->opcode, 0, 3);
    unsigned op = bits(i->opcode, 4, 4);
    if ( !op )
    {
      instr_s = "match";
      SET_INSTR_ID(out, AD_INSTR_MATCH);
    } else {
      instr_s = "nmatch";
      SET_INSTR_ID(out, AD_INSTR_NMATCH);
    }
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Pd);

    ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  if ( 5 == (op3 >> 3) )
  {
    // SVE2 Histogram Computation - Segment - page 2799
    unsigned op0 = bits(i->opcode, 10, 12);

    if ( op0 )
      return 1;
    SET_INSTR_ID(out, AD_INSTR_HISTSEG);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "histseg %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  if ( 6 == (op3 >> 3) )
  {
    // HISTCNT
    unsigned Pg = bits(i->opcode, 10, 12);

    SET_INSTR_ID(out, AD_INSTR_HISTCNT);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

    concat(DECODE_STR(out), "histcnt %s, %s, %s, %s", AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  if ( 7 == (op3 >> 3) )
  {
    // SVE2 Crypto Extensions - page 2800
    unsigned op0 = bits(i->opcode, 18, 20);
    unsigned op1 = bits(i->opcode, 16, 17);
    unsigned op2 = bits(i->opcode, 11, 12);
    unsigned op3 = bits(i->opcode, 5, 9);
    unsigned Zdn = bits(i->opcode, 0, 4);
    if ( !op0 && !op1 && !op2 && !op3 )
    {
      // SVE2 crypto unary operations - page 2800
      unsigned op = bits(i->opcode, 10, 10);
      if ( size )
        return 1;
      if ( !op )
      {
        instr_s = "aesmc";
        SET_INSTR_ID(out, AD_INSTR_AESMC);
      } else {
        instr_s = "aesimc";
        SET_INSTR_ID(out, AD_INSTR_AESIMC);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s", instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn]);
      return 0;
    }
    if ( 2 == op2 )
    {
      // SVE2 crypto constructive binary operation - page 2801
      unsigned op = bits(i->opcode, 10, 10);

      if ( size )
        return 1;
      if ( !op )
      {
        instr_s = "sm4ekey";
        SET_INSTR_ID(out, AD_INSTR_SM4EKEY);
      } else {
        instr_s = "rax1";
        SET_INSTR_ID(out, AD_INSTR_RAX1);
      }

      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( !op0 && (2 & op1) && !op2 )
    {
      // SVE2 crypto destructive binary operations - page 2800
      unsigned Zm = bits(i->opcode, 5, 9);
      unsigned op = bits(i->opcode, 16, 16);
      unsigned o2 = bits(i->opcode, 10, 10);
      unsigned idx = (op << 1 ) | o2;
      if ( size )
        return 1;
      if ( NULL == aes_tab[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, aes_tab[idx].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zdn);

      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", aes_tab[idx].instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    return 1;
  }
  return 1;
}

static int op03_op0_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 5, 9);
  unsigned Zdn = bits(i->opcode, 0, 4);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned size = bits(i->opcode, 22, 23);
  unsigned rot = bits(i->opcode, 16, 16);
  int sz = get_sz(size);

  if ( 4 != (op3 >> 3) )
    return 1;
  // fcadd
  SET_INSTR_ID(out, AD_INSTR_FCADD);
  ADD_FIELD(out, size);
  ADD_FIELD(out, rot);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zm);
  ADD_FIELD(out, Zdn);

  ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&rot);
  concat(DECODE_STR(out), "fcadd %s, %s, %s, %s, #%x", AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zdn], AD_RTBL_Z_128[Zm], rot);
  return 0;
}

static int op03_op0_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned opc = bits(i->opcode, 22, 23);
  unsigned opc2 = bits(i->opcode, 16, 17);
  const char *instr_s = NULL;

  if ( 5 != (op3 >> 3) )
    return 1;
  //  SVE floating-point convert precision odd elements - page 2801
  if ( !opc && (2 == opc2) )
  {
    instr_s = "fcvtxnt";
    SET_INSTR_ID(out, AD_INSTR_FCVTXNT);
  } else if ( (2 == opc) && !opc2 )
  {
    instr_s = "fcvtnt";
    SET_INSTR_ID(out, AD_INSTR_FCVTNT);
  } else if ( (2 == opc) && (1 == opc2) )
  {
    instr_s = "fcvtlt";
    SET_INSTR_ID(out, AD_INSTR_FCVTLT);
  } else if ( (2 == opc) && (2 == opc2) )
  {
    instr_s = "bfcvtnt";
    SET_INSTR_ID(out, AD_INSTR_BFCVTNT);
  } else if ( (3 == opc) && (2 == opc2) )
  {
    instr_s = "fcvtnt";
    SET_INSTR_ID(out, AD_INSTR_FCVTNT);
  } else if ( (3 == opc) && (3 == opc2) )
  {
    instr_s = "fcvtlt";
    SET_INSTR_ID(out, AD_INSTR_FCVTLT);
  } else
    return 1;

  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Zd);

  ADD_ZREG_OPERAND(out, Zd, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
  return 0;
}

static const struct itab fnp_tab[] = {
/* 0 0 0 */ { "faddp", AD_INSTR_FADDP },
/* 0 0 1 */ { NULL, AD_NONE },
/* 0 1 0 */ { NULL, AD_NONE },
/* 0 1 1 */ { NULL, AD_NONE },
/* 1 0 0 */ { "fmaxnmp", AD_INSTR_FMAXNMP },
/* 1 0 1 */ { "fminnmp", AD_INSTR_FMINNMP },
/* 1 1 0 */ { "fmaxp", AD_INSTR_FMAXP },
/* 1 1 1 */ { "fminp", AD_INSTR_FMINP },
};

static int op03_op0_op22(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 5, 9);
  unsigned Zdn = bits(i->opcode, 0, 4);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned size = bits(i->opcode, 22, 23);
  unsigned opc = bits(i->opcode, 16, 18);
  int sz = get_sz(size);

  if ( 4 != (op3 >> 3) )
    return 1;

  if ( NULL == fnp_tab[opc].instr_s )
    return 1;
  SET_INSTR_ID(out, fnp_tab[opc].instr_id);
  ADD_FIELD(out, size);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zm);
  ADD_FIELD(out, Zdn);

  ADD_ZREG_OPERAND(out, Zdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s, %s, %s, %s", fnp_tab[opc].instr_s, AD_RTBL_Z_128[Zdn], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm]);
  return 0;
}

static const struct itab mmla_tab[] = {
/* 0 0 */ { NULL, AD_NONE },
/* 0 1 */ { "bfmmla", AD_INSTR_BFMMLA },
/* 1 0 */ { "fmmla", AD_INSTR_FMMLA },
/* 1 1 */ { "fmmla", AD_INSTR_FMMLA },
};

static const struct itab fml_tab[] = {
/* 0 0 0 */ { "fmlalb", AD_INSTR_FMLALB },
/* 0 0 1 */ { "fmlalt", AD_INSTR_FMLALT },
/* 0 1 0 */ { "fmlslb", AD_INSTR_FMLSLB },
/* 0 1 1 */ { "fmlslt", AD_INSTR_FMLSLT },
/* 1 0 0 */ { "bfmlalb", AD_INSTR_BFMLALB },
/* 1 0 1 */ { "bfmlalt", AD_INSTR_BFMLALT },
/* 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 */ { NULL, AD_NONE },
};

static int fml_op(struct instruction *i, struct ad_insn *out)
{
   unsigned Zn = bits(i->opcode, 5, 9);
   unsigned Zd = bits(i->opcode, 0, 4);
   unsigned Zm = bits(i->opcode, 16, 18);
   unsigned op2 = bits(i->opcode, 22, 22);
   unsigned op = bits(i->opcode, 13, 13);
   unsigned T = bits(i->opcode, 10, 10);
   unsigned i3h = bits(i->opcode, 19, 20);
   unsigned i3l = bits(i->opcode, 11, 11);
   unsigned imm = (i3h << 1) | i3l;
   unsigned idx = (op2 << 2) | (op << 1) | T;
   if ( NULL == fml_tab[idx].instr_s )
     return 1;
   SET_INSTR_ID(out, fml_tab[idx].instr_id);
   ADD_FIELD(out, imm);
   ADD_FIELD(out, Zm);
   ADD_FIELD(out, Zn);
   ADD_FIELD(out, Zd);

   ADD_ZREG_OPERAND(out, Zd, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
   ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
   ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
   ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
   concat(DECODE_STR(out), "%s, %s, %s, %s, #%x", fml_tab[idx].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
   return 0;
}

static const struct itab fmla_ftab[] = {
/* 0 0 0 */ { "fmla", AD_INSTR_FMLA },
/* 0 0 1 */ { "fmls", AD_INSTR_FMLS },
/* 0 1 0 */ { "fmla", AD_INSTR_FMLA },
/* 0 1 1 */ { "fmls", AD_INSTR_FMLS },
/* 1 0 0 */ { "fmla", AD_INSTR_FMLA },
/* 1 0 1 */ { "fmla", AD_INSTR_FMLA },
/* 1 1 0 */ { "fmla", AD_INSTR_FMLA },
/* 1 1 1 */ { "fmla", AD_INSTR_FMLA },
};

static int op03_op0_op14(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);

  if ( !(op3 >> 1) )
  {
    // SVE floating-point multiply-add (indexed) - page 2802
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned imm = 0;
    if ( !(size & 2) )
    {
      unsigned i3h = bits(i->opcode, 22, 22);
      unsigned i3l = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
      imm = ( i3h << 2 ) | i3l;
    } else if ( 2 == size )
    {
      imm = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      imm = bits(i->opcode, 20, 20);
    } else
      return 1;

    SET_INSTR_ID(out, fmla_ftab[size].instr_id);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "%s, %s, %s, %s, #%x", fmla_ftab[size].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }
  if ( 1 == (op3 >> 2) )
  {
    // SVE floating-point complex multiply-add (indexed) - page 2802
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned imm = 0;
    if ( !(size & 2) )
      return 1;
    if ( 2 == size )
    {
      imm = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      imm = bits(i->opcode, 20, 20);
    } else
      return 1;
    SET_INSTR_ID(out, AD_INSTR_FCMLA);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "fcmla, %s, %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }
  if ( 8 == op3 )
  {
    // SVE floating-point multiply (indexed) - page 2802
    unsigned size = bits(i->opcode, 22, 23);
    int sz = get_sz(size);
    unsigned imm = 0;
    if ( !(size & 2) )
    {
      unsigned i3h = bits(i->opcode, 22, 22);
      unsigned i3l = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
      imm = ( i3h << 2 ) | i3l;
    } else if ( 2 == size )
    {
      imm = bits(i->opcode, 19, 20);
      Zm = bits(i->opcode, 16, 18);
    } else if ( 3 == size )
    {
      imm = bits(i->opcode, 20, 20);
    } else
      return 1;
    SET_INSTR_ID(out, AD_INSTR_FMUL);
    ADD_FIELD(out, imm);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
    concat(DECODE_STR(out), "fmul, %s, %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
    return 0;
  }
  // 01x0xx
  if ( 1 == (op3 >> 4) && !(op3 & 4) )
  {
    // SVE Floating Point Widening Multiply-Add - Indexed - page 2802
    unsigned op0 = bits(i->opcode, 23, 23);
    unsigned op1 = bits(i->opcode, 13, 13);
    unsigned op2 = bits(i->opcode, 10, 11);
    if ( !op0 && !op2 )
    {
      // SVE floating-point multiply-add long (indexed) - page 2803
      unsigned op = bits(i->opcode, 22, 22);
      unsigned imm = bits(i->opcode, 19, 20);
      if ( !op )
        return 1;
      Zm = bits(i->opcode, 16, 18);
      SET_INSTR_ID(out, AD_INSTR_BFDOT);
      ADD_FIELD(out, imm);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "bfdot, %s, %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm], imm);
      return 0;
    }
    if ( 1 == op0 )
    {
      // SVE floating-point multiply-add long (indexed) - page 2802
      return fml_op(i, out);
    }
    return 1;
  }
  // 10x00x
  if ( 2 == (op3 >> 4) && !(op3 & 6) )
  {
    // SVE Floating Point Widening Multiply-Add - page 2803
    return fml_op(i, out);
  }
  // last valid 111001
  if ( 57 == op3 )
  {
    // SVE floating point matrix multiply accumulate - page 2804
    unsigned opc = bits(i->opcode, 22, 23);
    unsigned sz = _32_BIT;
    if ( 3 == opc )
     sz = _64_BIT;
    if ( NULL == mmla_tab[opc].instr_s )
      return 1;
    SET_INSTR_ID(out, mmla_tab[opc].instr_id);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s, %s, %s, %s", mmla_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  return 1;
}

static const struct itab fcm_tab[] = {
/* 0 0 0 */ { "fcmge", AD_INSTR_FCMGE },
/* 0 0 1 */ { "fcmgt", AD_INSTR_FCMGT },
/* 0 1 0 */ { "fcmeq", AD_INSTR_FCMEQ },
/* 0 1 1 */ { "fcmne", AD_INSTR_FCMNE },
/* 1 0 0 */ { "fcmuo", AD_INSTR_FCMUO },
/* 1 0 1 */ { "facge", AD_INSTR_FACGE },
/* 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 */ { "facgt", AD_INSTR_FACGT },
};

static const struct itab fari_tab[] = {
/* 0 0 0 */ { "fadd", AD_INSTR_FADD },
/* 0 0 1 */ { "fsub", AD_INSTR_FSUB },
/* 0 1 0 */ { "fmul", AD_INSTR_FMUL },
/* 0 1 1 */ { "ftsmul", AD_INSTR_FTSMUL },
/* 1 0 0 */ { NULL, AD_NONE },
/* 1 0 1 */ { NULL, AD_NONE },
/* 1 1 0 */ { "frecps", AD_INSTR_FRECPS },
/* 1 1 1 */ { "frsqrts", AD_INSTR_FRSQRTS },
};

static const struct itab fari2_tab[] = {
/* 0 0 0 0 */ { "fadd", AD_INSTR_FADD },
/* 0 0 0 1 */ { "fsub", AD_INSTR_FSUB },
/* 0 0 0 1 */ { "fmul", AD_INSTR_FMUL },
/* 0 0 1 1 */ { "fsubr", AD_INSTR_FSUBR },
/* 0 1 0 0 */ { "fmaxnm", AD_INSTR_FMAXNM },
/* 0 1 0 1 */ { "fminnm", AD_INSTR_FMINNM },
/* 0 1 1 0 */ { "fmax", AD_INSTR_FMAX },
/* 0 1 1 1 */ { "fmin", AD_INSTR_FMIN },
/* 1 0 0 0 */ { "fabd", AD_INSTR_FABD },
/* 1 0 0 1 */ { "fscale", AD_INSTR_FSCALE },
/* 1 0 1 0 */ { "fmulx", AD_INSTR_FMULX },
/* 1 0 1 1 */ { NULL, AD_NONE },
/* 1 1 0 0 */ { "fdivr", AD_INSTR_FDIVR },
/* 1 1 0 1 */ { "fdiv", AD_INSTR_FDIV },
/* 1 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 1 */ { NULL, AD_NONE },
};

static const struct itab fari3_ftab[] = {
/* 0 0 0 */ { "fadd", AD_INSTR_FADD },
/* 0 0 1 */ { "fsub", AD_INSTR_FSUB },
/* 0 1 0 */ { "fmul", AD_INSTR_FMUL },
/* 0 1 1 */ { "fsubr", AD_INSTR_FSUBR },
/* 1 0 0 */ { "fmaxnm", AD_INSTR_FMAXNM },
/* 1 0 1 */ { "fminnm", AD_INSTR_FMINNM },
/* 1 1 0 */ { "fmax", AD_INSTR_FMAX },
/* 1 1 1 */ { "fmin", AD_INSTR_FMIN },
};

static const struct itab frint_tab[] = {
/* 0 0 0 */ { "frintn", AD_INSTR_FRINTN },
/* 0 0 1 */ { "frintp", AD_INSTR_FRINTP },
/* 0 1 0 */ { "frintm", AD_INSTR_FRINTM },
/* 0 1 1 */ { "frintz", AD_INSTR_FRINTZ },
/* 1 0 0 */ { "frinta", AD_INSTR_FRINTA },
/* 1 0 1 */ { NULL, AD_NONE },
/* 1 1 0 */ { "frintx", AD_INSTR_FRINTX },
/* 1 1 1 */ { "frinti", AD_INSTR_FRINTI },
};

static const struct itab fcv_tab[] = {
/* 0 0 0 0 */ { NULL, AD_NONE },
/* 0 0 0 1 */ { NULL, AD_NONE },
/* 0 0 1 0 */ { "fcvtx", AD_INSTR_FCVTX },
/* 0 0 1 1 */ { NULL, AD_NONE },
/* 0 1 0 0 */ { NULL, AD_NONE },
/* 0 1 0 1 */ { NULL, AD_NONE },
/* 0 1 1 0 */ { NULL, AD_NONE },
/* 0 1 1 1 */ { NULL, AD_NONE },
/* 1 0 0 0 */ { "fcvt", AD_INSTR_FCVT },
/* 1 0 0 1 */ { "fcvt", AD_INSTR_FCVT },
/* 1 0 1 0 */ { "bfcvt", AD_INSTR_FCVT },
/* 1 0 1 1 */ { NULL, AD_NONE },
/* 1 1 0 0 */ { "fcvt", AD_INSTR_FCVT },
/* 1 1 0 1 */ { "fcvt", AD_INSTR_FCVT },
/* 1 1 1 0 */ { "fcvt", AD_INSTR_FCVT },
/* 1 1 1 1 */ { "fcvt", AD_INSTR_FCVT },
};

static int op03_op1_op40(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned Pg = bits(i->opcode, 10, 12);
  // x1xxxx
  if ( 1 & (op3 >> 4) )
  {
    // SVE floating-point compare vectors - page 2805
    unsigned Pd = bits(i->opcode, 0, 3);
    unsigned o3 = bits(i->opcode, 4, 4);
    unsigned o2 = bits(i->opcode, 13, 13);
    unsigned op = bits(i->opcode, 15, 15);
    int idx = (op << 2) | (o2 << 1) | o3;
    if ( NULL == fcm_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, fcm_tab[idx].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Pd);

    ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);

    concat(DECODE_STR(out), "%s %s, %s, %s, %s", fcm_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  // 000xxx
  if ( !(op3 >> 3) ) 
  {
    // SVE Floating Point Arithmetic - Predicated - page 2805
    unsigned opc = bits(i->opcode, 10, 12);

    if ( NULL == fari_tab[opc].instr_s )
      return 1;

    SET_INSTR_ID(out, fari_tab[opc].instr_id);
    ADD_FIELD(out, size);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zd);

    ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s", fari_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Zm]);
    return 0;
  }
  // 100xxx
  if ( 4 == (op3 >> 3) ) 
  {
    // SVE Floating Point Arithmetic - Predicated - page 2805
    unsigned op0 = bits(i->opcode, 19, 20);
    unsigned op1 = bits(i->opcode, 13, 15);
    unsigned op2 = bits(i->opcode, 6, 9);
    if ( !(op0 & 2) ) 
    {
      // SVE floating-point arithmetic (predicated) - page 2806
      unsigned opc = bits(i->opcode, 16, 19);
      if ( NULL == fari2_tab[opc].instr_s )
        return 1;
      SET_INSTR_ID(out, fari2_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", fari2_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zm]);
      return 0;
    }
    if ( (2 == op0) && !op1 )
    {
      // ftmad - page 1680
      unsigned imm3 = bits(i->opcode, 16, 18);
      SET_INSTR_ID(out, AD_INSTR_FTMAD);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm3);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm3);
      concat(DECODE_STR(out), "ftmad %s, %s, %s, #%x", AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zm], imm3);
      return 0;
    }
    if ( (3 == op0 ) && !op2 )
    {
      // SVE floating-point arithmetic with immediate (predicated) - page 2806
      unsigned opc = bits(i->opcode, 16, 18);
      unsigned imm = bits(i->opcode, 5, 5);

      SET_INSTR_ID(out, fari3_ftab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, imm);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", fari3_ftab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zd], imm);
      return 0;
    }
    return 1;
  }
  // 101xxx
  if ( 5 == (op3 >> 3) ) 
  {
    // SVE Floating Point Unary Operations - Predicated - page 2807
    unsigned op0 = bits(i->opcode, 18, 20);
    if ( !(op0 >> 1) )
    {
      // SVE floating-point round to integral value - page 2807
      unsigned opc = bits(i->opcode, 16, 18);
      if ( NULL == frint_tab[opc].instr_s )
        return 1;
      SET_INSTR_ID(out, frint_tab[opc].instr_id);
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", frint_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE floating-point convert precision - page 2807
      unsigned opc = bits(i->opcode, 22, 23);
      unsigned opc2 = bits(i->opcode, 16, 17);
      sz = get_sz(opc);

      if ( NULL == fcv_tab[opc].instr_s )
        return 1;
      SET_INSTR_ID(out, fcv_tab[opc].instr_id);
      ADD_FIELD(out, opc);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", fcv_tab[opc].instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE floating-point unary operations - page 2807
      unsigned opc = bits(i->opcode, 16, 17);
      const char *instr_s = NULL;
      if ( opc > 1 )
        return 1;
      if ( !opc )
      {
        instr_s = "frecpx";
        SET_INSTR_ID(out, AD_INSTR_FRECPX);
      } else {
        instr_s = "fsqrt";
        SET_INSTR_ID(out, AD_INSTR_FSQRT);
      }
      ADD_FIELD(out, size);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 2 == (op0 >> 1) )
    {
      // SVE integer convert to floating-point - page 2802
      unsigned opc = bits(i->opcode, 22, 23);
      unsigned opc2 = bits(i->opcode, 17, 18);
      unsigned U = bits(i->opcode, 16, 16);
      unsigned idx = (opc << 3) | (opc2 << 1) | U;
      const char *instr_s = NULL;
      if ( !opc )
        return 1;
      sz = get_sz(opc);
      switch(idx)
      {
        case 0x1E:
        case 0x1C:
        case 0x18:
        case 0x14:
        case 0xE:
        case 0xC:
        case 0xA: instr_s = "scvtf";
                   SET_INSTR_ID(out, AD_INSTR_SCVTF);
          break;

        case 0x1f:
        case 0x1d:
        case 0x19:
        case 0x15:
        case 0xf:
        case 0xd:
        case 0xB: instr_s = "ucvtf";
                   SET_INSTR_ID(out, AD_INSTR_UCVTF);
          break;
        default: return 1;
      }
      ADD_FIELD(out, opc);
      ADD_FIELD(out, opc2);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    if ( 3 == (op0 >> 1) )
    {
      // SVE floating-point convert to integer - page 2808
      unsigned opc = bits(i->opcode, 22, 23);
      unsigned opc2 = bits(i->opcode, 17, 18);
      unsigned U = bits(i->opcode, 16, 16);
      unsigned idx = (opc << 3) | (opc2 << 1) | U;
      const char *instr_s = NULL;
      if ( !opc )
        return 1;
      sz = get_sz(opc);
      if ( !opc && !U )
      {
        instr_s = "flogb";
        SET_INSTR_ID(out, AD_INSTR_FLOGB);
      }
      switch(idx)
      {
        case 0x1E:
        case 0x1C:
        case 0x18:
        case 0x14:
        case 0xE:
        case 0xC:
        case 0xA: instr_s = "fcvtzs";
                   SET_INSTR_ID(out, AD_INSTR_FCVTZS);
          break;

        case 0x1f:
        case 0x1d:
        case 0x19:
        case 0x15:
        case 0xf:
        case 0xd:
        case 0xB: instr_s = "fcvtzu";
                   SET_INSTR_ID(out, AD_INSTR_FCVTZU);
          break;
      }
      if ( NULL == instr_s )
        return 1;

      ADD_FIELD(out, opc);
      ADD_FIELD(out, opc2);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zd);

      ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
      return 0;
    }
    return 1;
  }
  return 1;
}

static const struct itab fmv_tab[] = {
/* 0 0 0 */ { "fadd", AD_INSTR_FADD },
/* 0 0 1 */ { NULL, AD_NONE },
/* 0 1 0 */ { NULL, AD_NONE },
/* 0 1 1 */ { NULL, AD_NONE },
/* 1 0 0 */ { "fmaxnmv", AD_INSTR_FMAXNMV },
/* 1 0 1 */ { "fminnmv", AD_INSTR_FMINNMV },
/* 1 1 0 */ { "fmaxv", AD_INSTR_FMAXV },
/* 1 1 1 */ { "fminv", AD_INSTR_FMINV },
};

static int op03_op1_op20(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Vd = bits(i->opcode, 0, 4);
  unsigned opc = bits(i->opcode, 16, 18);
  // SVE floating-point recursive reduction - page 2809
  if ( 1 != (op3 >> 3) )
    return 1;
  if ( NULL == fmv_tab[opc].instr_s )
    return 1;

  SET_INSTR_ID(out, fmv_tab[opc].instr_id);
  ADD_FIELD(out, size);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Vd);

  ADD_REG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s %s, %s, %s", fmv_tab[opc].instr_s, AD_RTBL_FP_V_128[Vd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
  return 0;
}

static int op03_op1_op21(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned op0 = bits(i->opcode, 10, 11);
  unsigned size = bits(i->opcode, 22, 23);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);
  int sz = get_sz(size);
  const char *instr_s = NULL;
  unsigned opc = bits(i->opcode, 16, 18);
  // SVE Floating Point Unary Operations - Unpredicated - page 2809
  if ( 3 != (op3 >> 2) )
    return 1;
  if ( op0 )
    return 1;
  if ( opc == 6 )
  {
    instr_s = "frecpe";
    SET_INSTR_ID(out, AD_INSTR_FRECPE);
  } else if ( opc == 7 )
  {
    instr_s = "frsqrte";
    SET_INSTR_ID(out, AD_INSTR_FRSQRTE);
  } else
    return 1;

  ADD_FIELD(out, size);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Zd);

  ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_Z_128[Zn]);
  return 0;

}

static int op03_op1_op22(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  // SVE Floating Point Compare - with Zero - page 2810
  unsigned op0 = bits(i->opcode, 18, 18);
  unsigned Pd = bits(i->opcode, 0, 3);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned ne = bits(i->opcode, 4, 4);
  unsigned lt = bits(i->opcode, 16, 16);
  unsigned eq = bits(i->opcode, 17, 17);
  int idx = (eq << 2) | (lt << 1) | ne;
  if ( 1 != (op3 >> 3) ) 
    return 1;
  if ( op0 )
    return 1;
  if ( NULL == fcm_tab[idx].instr_s )
    return 1;

  SET_INSTR_ID(out, fcm_tab[idx].instr_id);
  ADD_FIELD(out, size);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Pd);

  ADD_ZREG_OPERAND(out, Pd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s %s, %s, %s, #0.0", fcm_tab[idx].instr_s, AD_RTBL_PG_128[Pd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn]);
  return 0;
}

static int op03_op1_op23(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  // SVE floating-point serial reduction (predicated) - page 2810
  unsigned opc = bits(i->opcode, 16, 18);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Zm = bits(i->opcode, 5, 9);
  unsigned Vdn = bits(i->opcode, 0, 4);
  if ( 1 != (op3 >> 3) ) 
    return 1;
  if ( opc )
    return 1;
  SET_INSTR_ID(out, AD_INSTR_FADDA);
  ADD_FIELD(out, size);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zm);
  ADD_FIELD(out, Vdn);

  ADD_REG_OPERAND(out, Vdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_REG_OPERAND(out, Vdn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_FP_V_128));
  ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "fadda %s %s, %s, %s", AD_RTBL_FP_V_128[Vdn], AD_RTBL_PG_128[Pg], AD_RTBL_FP_V_128[Vdn], AD_RTBL_Z_128[Zm]);
  return 0;
}

static const struct itab fmla_tab2[] = {
/* 0 0 */ { "fmla", AD_INSTR_FMLA },
/* 0 1 */ { "fmls", AD_INSTR_FMLS },
/* 1 0 */ { "fnmla", AD_INSTR_FNMLA },
/* 1 1 */ { "fnmls", AD_INSTR_FNMLS },
};

static const struct itab fmad_ftab[] = {
/* 0 0 */ { "fmad", AD_INSTR_FMAD },
/* 0 1 */ { "fmsb", AD_INSTR_FMSB },
/* 1 0 */ { "fnmad", AD_INSTR_FNMAD },
/* 1 1 */ { "fnmsb", AD_INSTR_FNMSB },
};

static int op03_op1_op14(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  // SVE Floating Point Multiply-Add - page 2811
  unsigned op0 = bits(i->opcode, 15, 15);
  unsigned size = bits(i->opcode, 22, 23);
  int sz = get_sz(size);
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Zn = bits(i->opcode, 5, 9);
  unsigned Zd = bits(i->opcode, 0, 4);
  unsigned opc = bits(i->opcode, 13, 14);
  const char *instr_s = NULL;
  if ( !op0 )
  {
    instr_s = fmla_tab2[opc].instr_s;
    SET_INSTR_ID(out, fmla_tab2[opc].instr_id);
  } else {
    instr_s = fmad_ftab[opc].instr_s;
    SET_INSTR_ID(out, fmad_ftab[opc].instr_id);
  }
  ADD_FIELD(out, size);
  ADD_FIELD(out, Zm);
  ADD_FIELD(out, Pg);
  ADD_FIELD(out, Zn);
  ADD_FIELD(out, Zd);

  ADD_ZREG_OPERAND(out, Zd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
  ADD_ZREG_OPERAND(out, Zn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  ADD_ZREG_OPERAND(out, Zm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
  concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zd], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zm], AD_RTBL_Z_128[Zn]);
  return 0;
}

static const struct itab prf_tab[] = {
/* 0 0 */ { "prfb", AD_INSTR_PRFB },
/* 0 1 */ { "prfh", AD_INSTR_PRFH },
/* 1 0 */ { "prfw", AD_INSTR_PRFW },
/* 1 1 */ { "prfd", AD_INSTR_PRFD },
};

// ripped from page 2057
static const char *const prfop_name[] = {
/* 0 0 0 0 */ "PLDL1KEEP",
/* 0 0 0 1 */ "PLDL1STRM",
/* 0 0 1 0 */ "PLDL2KEEP",
/* 0 0 1 1 */ "PLDL2STRM",
/* 0 1 0 0 */ "PLDL3KEEP",
/* 0 1 0 1 */ "PLDL3STRM",
/* 0 1 1 0 */ NULL,
/* 0 1 1 1 */ NULL,
/* 1 0 0 0 */ "PSTL1KEEP",
/* 1 0 0 1 */ "PSTL1STRM",
/* 1 0 1 0 */ "PSTL2KEEP",
/* 1 0 1 1 */ "PSTL2STRM",
/* 1 1 0 0 */ "PSTL3KEEP",
/* 1 1 0 1 */ "PSTL3STRM",
/* 1 1 1 0 */ NULL,
/* 1 1 1 1 */ NULL
};

static const struct itab ld1_tab[] = {
/* 0 0 */ { "ld1sh", AD_INSTR_LD1SH },
/* 0 1 */ { "ldff1sh", AD_INSTR_LDFF1SH },
/* 1 0 */ { "ld1h", AD_INSTR_LD1H },
/* 1 1 */ { "ldff1h", AD_INSTR_LDFF1H },
};

static const struct itab ld1_tab2[] = {
/* 0 0 */ { NULL, AD_NONE },
/* 0 1 */ { NULL, AD_NONE },
/* 1 0 */ { "ld1w", AD_INSTR_LD1W },
/* 1 1 */ { "ldff1w", AD_INSTR_LDFF1W },
};

static const struct itab ld1_tab3[] = {
/* 00 0 0 */ { "ld1sb", AD_INSTR_LD1SB },
/* 00 0 1 */ { "ldff1sb", AD_INSTR_LDFF1SB },
/* 00 1 0 */ { "ld1b", AD_INSTR_LD1B },
/* 00 1 1 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 01 0 0 */ { "ld1sh", AD_INSTR_LD1SH },
/* 01 0 1 */ { "ldff1sh", AD_INSTR_LDFF1SH },
/* 01 1 0 */ { "ld1h", AD_INSTR_LD1H },
/* 01 1 1 */ { "ldff1h", AD_INSTR_LDFF1H },
/* 10 0 0 */ { NULL, AD_NONE },
/* 10 0 1 */ { NULL, AD_NONE },
/* 10 1 0 */ { "ld1w", AD_INSTR_LD1W },
/* 10 1 1 */ { "ldff1w", AD_INSTR_LDFF1W },
};

static const struct itab ldn_tab[] = {
/* 0 0 0 */ { "ldnt1sb", AD_INSTR_LDNT1SB },
/* 0 0 1 */ { "ldnt1b", AD_INSTR_LDNT1B },
/* 0 1 0 */ { "ldnt1sh", AD_INSTR_LDNT1SH },
/* 0 1 1 */ { "ldnt1h", AD_INSTR_LDNT1H },
/* 1 0 0 */ { NULL, AD_NONE },
/* 1 0 1 */ { "ldnt1w", AD_INSTR_LDNT1W },
/* 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 */ { NULL, AD_NONE },
};

static const struct itab ld1_ftab[] = {
/* 0 0 0 0 */ { "ld1rb", AD_INSTR_LD1RB },
/* 0 0 0 1 */ { "ld1rb", AD_INSTR_LD1RB },
/* 0 0 1 0 */ { "ld1rb", AD_INSTR_LD1RB },
/* 0 0 1 1 */ { "ld1rb", AD_INSTR_LD1RB },
/* 0 1 0 0 */ { "ld1rsw", AD_INSTR_LD1RSW },
/* 0 1 0 1 */ { "ld1rh", AD_INSTR_LD1RH },
/* 0 1 1 0 */ { "ld1rh", AD_INSTR_LD1RH },
/* 0 1 1 1 */ { "ld1rh", AD_INSTR_LD1RH },
/* 1 0 0 0 */ { "ld1rsh", AD_INSTR_LD1RSH },
/* 1 0 0 1 */ { "ld1rsh", AD_INSTR_LD1RSH },
/* 1 0 1 0 */ { "ld1rw", AD_INSTR_LD1RW },
/* 1 0 1 1 */ { "ld1rw", AD_INSTR_LD1RW },
/* 1 1 0 0 */ { "ld1rsb", AD_INSTR_LD1RSB },
/* 1 1 0 1 */ { "ld1rsb", AD_INSTR_LD1RSB },
/* 1 1 1 0 */ { "ld1rsb", AD_INSTR_LD1RSB },
/* 1 1 1 1 */ { "ld1rd", AD_INSTR_LD1RD },
};

static int op04(struct instruction *i, struct ad_insn *out)
{
  // SVE Memory - 32-bit Gather and Unsized Contiguous - page 2811
  unsigned op0 = bits(i->opcode, 23, 24);
  unsigned op1 = bits(i->opcode, 21, 22);
  unsigned op2 = bits(i->opcode, 13, 15);
  unsigned op3 = bits(i->opcode, 4, 4);

  unsigned xs = bits(i->opcode, 22, 22);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Rn = bits(i->opcode, 5, 9);
  unsigned Zm = bits(i->opcode, 16, 20);

  if ( !op0 )
  {
    if ( (op1 & 1) && !(op2 >> 2) && !op3 )
    {
      // SVE 32-bit gather prefetch (scalar plus 32-bit scaled offsets) - page 2812
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned prfop = bits(i->opcode, 0, 3);
      unsigned msz = bits(i->opcode, 13, 14);

      SET_INSTR_ID(out, prf_tab[msz].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, prfop);

      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      if ( prfop_name[prfop] != NULL )
        concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      else
        concat(DECODE_STR(out), "%s #%x, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
  }
  if ( 1 == op0 )
  {
    if ( (op1 & 1) && !(op2 >> 2) )
    {
      // SVE 32-bit gather load halfwords (scalar plus 32-bit scaled offsets) - page 2812
      unsigned U = bits(i->opcode, 14, 14);
      unsigned ff = bits(i->opcode, 13, 13);
      unsigned Zt = bits(i->opcode, 0, 4);
      unsigned idx = (U << 1) | ff;
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

      SET_INSTR_ID(out, ld1_tab[idx].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
  }
  if ( 2 == op0 )
  {
    if ( (op1 & 1) && !(op2 >> 2) )
    {
      // SVE 32-bit gather load words (scalar plus 32-bit scaled offsets) - page 2812
      unsigned U = bits(i->opcode, 14, 14);
      unsigned ff = bits(i->opcode, 13, 13);
      unsigned Zt = bits(i->opcode, 0, 4);
      unsigned idx = (U << 1) | ff;
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

      if ( NULL == ld1_tab2[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, ld1_tab2[idx].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab2[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
  }
  if ( 3 == op0 )
  {
    if ( !(2 & op1) && !op2 && !op3 )
    {
      // ldr
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned Pt = bits(i->opcode, 0, 3);
      unsigned imm9h = bits(i->opcode, 16, 21);
      unsigned imm9l = bits(i->opcode, 10, 12);
      unsigned imm = (imm9h << 3) | imm9l;

      SET_INSTR_ID(out, AD_INSTR_LDR);
      ADD_FIELD(out, imm9h);
      ADD_FIELD(out, imm9l);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Pt);

      ADD_ZREG_OPERAND(out, Pt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "ldr %s, %s, #%x", AD_RTBL_PG_128[Pt], Rn_s, imm);
      return 0;
    }
    if ( !(2 & op1) && (2 == op2) )
    {
      // ldr vector
      unsigned Zt = bits(i->opcode, 0, 4);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned imm9h = bits(i->opcode, 16, 21);
      unsigned imm9l = bits(i->opcode, 10, 12);
      unsigned imm = (imm9h << 3) | imm9l;

      SET_INSTR_ID(out, AD_INSTR_LDR);
      ADD_FIELD(out, imm9h);
      ADD_FIELD(out, imm9l);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "ldr %s, %s, #%x", AD_RTBL_Z_128[Zt], Rn_s, imm);
      return 0;
    }
    if ( (2 & op1) && !(op2 >> 2) && !op3 )
    {
      // SVE contiguous prefetch (scalar plus immediate) - page 2812
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned prfop = bits(i->opcode, 0, 3);
      unsigned msz = bits(i->opcode, 13, 14);
      unsigned imm = bits(i->opcode, 16, 21);

      SET_INSTR_ID(out, prf_tab[msz].instr_id);
      ADD_FIELD(out, imm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, prfop);

      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      if ( prfop_name[prfop] != NULL )
        concat(DECODE_STR(out), "%s %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, imm);
      else
        concat(DECODE_STR(out), "%s #%x, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, imm);
      return 0;
    }
  }
  if ( 3 != op0 )
  {
    if ( !(op1 & 1) && !(op2 >> 2) )
    {
      // SVE 32-bit gather load (scalar plus 32-bit unscaled offsets) - page 2813
      unsigned opc = bits(i->opcode, 23, 24);
      unsigned U = bits(i->opcode, 14, 14);
      unsigned ff = bits(i->opcode, 13, 13);
      unsigned Zt = bits(i->opcode, 0, 4);
      unsigned idx = (opc << 2) | (U << 1) | ff;
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      if ( OOB(idx, ld1_tab3) )
        return 1;
      if ( NULL == ld1_tab3[idx].instr_s )
        return 1;

      SET_INSTR_ID(out, ld1_tab3[idx].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab3[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
  }
  if ( !op1 && (2 == (op2 >> 1)) )
  {
    // SVE2 32-bit gather non-temporal load (scalar plus 32-bit unscaled offsets) - page 2813
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned U = bits(i->opcode, 13, 13);
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned Zt = bits(i->opcode, 0, 4);
    unsigned Zn = bits(i->opcode, 5, 9);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
    unsigned idx = (msz << 1) | U;
    if ( OOB(idx, ldn_tab) )
      return 1;
    if ( NULL == ldn_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, ldn_tab[idx].instr_id);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_REG_OPERAND(out, Rm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ldn_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], Rm_s);
    return 0;
  }
  if ( !op1 && (6 == op2) && !op3 )
  {
    // SVE contiguous prefetch (scalar plus scalar) - page 2814
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    unsigned prfop = bits(i->opcode, 0, 3);
    unsigned Rm = Zm;
    unsigned msz = bits(i->opcode, 23, 24);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
    SET_INSTR_ID(out, prf_tab[msz].instr_id);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, prfop);

    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    if ( prfop_name[prfop] != NULL )
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    else
      concat(DECODE_STR(out), "%s #%x, %s, %s, %s", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  if ( !op1 && (7 == op2) && !op3 )
  {
    // SVE 32-bit gather prefetch (vector plus immediate) - page 2814
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned Zn = Rn;
    unsigned prfop = bits(i->opcode, 0, 3);
    unsigned imm5 = bits(i->opcode, 16, 20);

    SET_INSTR_ID(out, prf_tab[msz].instr_id);
    ADD_FIELD(out, imm5);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, prfop);

    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
    if ( prfop_name[prfop] != NULL )
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    else
      concat(DECODE_STR(out), "%s #%x, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    return 0;
  }
  if ( (1 == op1) && (1 == (op2 >> 2)) )
  {
    // SVE 32-bit gather load (vector plus immediate) - page 2814
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned Zn = Rn;
    unsigned U = bits(i->opcode, 14, 14);
    unsigned ff = bits(i->opcode, 13, 13);
    unsigned Zt = bits(i->opcode, 0, 4);
    unsigned idx = (msz << 2) | (U << 1) | ff;
    unsigned imm5 = bits(i->opcode, 16, 20);

    if ( OOB(idx, ld1_tab3) )
      return 1;
    if ( NULL == ld1_tab3[idx].instr_s )
      return 1;
 
    SET_INSTR_ID(out, ld1_tab3[idx].instr_id);
    ADD_FIELD(out, imm5);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab3[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    return 0;
  }
  if ( (2 & op1) && (1 == (op2 >> 2)) )
  {
    // SVE load and broadcast element - page 2814
    unsigned imm6 = bits(i->opcode, 16, 21);
    unsigned dtypeh = bits(i->opcode, 23, 24);
    unsigned dtypel = bits(i->opcode, 13, 14);
    unsigned Zt = bits(i->opcode, 0, 4);
    unsigned idx = (dtypeh << 2) | dtypel;
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    int sz = get_sz(dtypel);

    SET_INSTR_ID(out, ld1_ftab[idx].instr_id);
    ADD_FIELD(out, dtypeh);
    ADD_FIELD(out, imm6);
    ADD_FIELD(out, dtypel);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm6);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_ftab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm6);
    return 0;
  }
  return 1;
}

static const struct itab ldn_tab2[] = {
/* 0 0 */ { "ldnt1b", AD_INSTR_LDNT1B },
/* 0 1 */ { "ldnt1h", AD_INSTR_LDNT1H },
/* 1 0 */ { "ldnt1w", AD_INSTR_LDNT1W },
/* 1 1 */ { "ldnt1d", AD_INSTR_LDNT1D },
};

static const struct itab ld2_tab[] = {
/* 0 0 0 0 */ { NULL, AD_NONE },
/* 0 0 0 1 */ { "ld2b", AD_INSTR_LD2B },
/* 0 0 1 0 */ { "ld3b", AD_INSTR_LD3B },
/* 0 0 1 1 */ { "ld4b", AD_INSTR_LD4B },
/* 0 1 0 0 */ { NULL, AD_NONE },
/* 0 1 0 1 */ { "ld2h", AD_INSTR_LD2H },
/* 0 1 1 0 */ { "ld3h", AD_INSTR_LD3H },
/* 0 1 1 1 */ { "ld4h", AD_INSTR_LD4H },
/* 1 0 0 0 */ { NULL, AD_NONE },
/* 1 0 0 1 */ { "ld2w", AD_INSTR_LD2W },
/* 1 0 1 0 */ { "ld3w", AD_INSTR_LD3W },
/* 1 0 1 1 */ { "ld4w", AD_INSTR_LD4W },
/* 1 1 0 0 */ { NULL, AD_NONE },
/* 1 1 0 1 */ { "ld2d", AD_INSTR_LD2D },
/* 1 1 1 0 */ { "ld3d", AD_INSTR_LD3D },
/* 1 1 1 1 */ { "ld4d", AD_INSTR_LD4D },
};

static const struct itab ld1r_tab[] = {
/* 0 0 0 0 */ { "ld1rqb", AD_INSTR_LD1RQB },
/* 0 0 0 1 */ { "ld1rob", AD_INSTR_LD1ROB },
/* 0 0 1 0 */ { NULL, AD_NONE },
/* 0 0 1 1 */ { NULL, AD_NONE },
/* 0 1 0 0 */ { "ld1rqh", AD_INSTR_LD1RQH },
/* 0 1 0 1 */ { "ld1roh", AD_INSTR_LD1ROH },
/* 0 1 1 0 */ { NULL, AD_NONE },
/* 0 1 1 1 */ { NULL, AD_NONE },
/* 1 0 0 0 */ { "ld1rqw", AD_INSTR_LD1RQW },
/* 1 0 0 1 */ { "ld1row", AD_INSTR_LD1ROW },
/* 1 0 1 0 */ { NULL, AD_NONE },
/* 1 0 1 1 */ { NULL, AD_NONE },
/* 1 1 0 0 */ { "ld1rqd", AD_INSTR_LD1RQD },
/* 1 1 0 1 */ { "ld1rod", AD_INSTR_LD1ROD },
/* 1 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 1 */ { NULL, AD_NONE },
};

static const struct itab ld1_tab5[] = {
/* 0 0 0 0 */ { "ld1b", AD_INSTR_LD1B },
/* 0 0 0 1 */ { "ld1b", AD_INSTR_LD1B },
/* 0 0 1 0 */ { "ld1b", AD_INSTR_LD1B },
/* 0 0 1 1 */ { "ld1b", AD_INSTR_LD1B },
/* 0 1 0 0 */ { "ld1sw", AD_INSTR_LD1SW },
/* 0 1 0 1 */ { "ld1h", AD_INSTR_LD1H },
/* 0 1 1 0 */ { "ld1h", AD_INSTR_LD1H },
/* 0 1 1 1 */ { "ld1h", AD_INSTR_LD1H },
/* 1 0 0 0 */ { "ld1sh", AD_INSTR_LD1SH },
/* 1 0 0 1 */ { "ld1sh", AD_INSTR_LD1SH },
/* 1 0 1 0 */ { "ld1w", AD_INSTR_LD1W },
/* 1 0 1 1 */ { "ld1w", AD_INSTR_LD1W },
/* 1 1 0 0 */ { "ld1sb", AD_INSTR_LD1SB },
/* 1 1 0 1 */ { "ld1sb", AD_INSTR_LD1SB },
/* 1 1 1 0 */ { "ld1sb", AD_INSTR_LD1SB },
/* 1 1 1 1 */ { "ld1d", AD_INSTR_LD1D },
};

static const struct itab ldnf_ftab[] = {
/* 0 0 0 0 */ { "ldnf1b", AD_INSTR_LDNF1B },
/* 0 0 0 1 */ { "ldnf1b", AD_INSTR_LDNF1B },
/* 0 0 1 0 */ { "ldnf1b", AD_INSTR_LDNF1B },
/* 0 0 1 1 */ { "ldnf1b", AD_INSTR_LDNF1B },
/* 0 1 0 0 */ { "ldnf1sw", AD_INSTR_LDNF1SW },
/* 0 1 0 1 */ { "ldnf1h", AD_INSTR_LDNF1H },
/* 0 1 1 0 */ { "ldnf1h", AD_INSTR_LDNF1H },
/* 0 1 1 1 */ { "ldnf1h", AD_INSTR_LDNF1H },
/* 1 0 0 0 */ { "ldnf1sh", AD_INSTR_LDNF1SH },
/* 1 0 0 1 */ { "ldnf1sh", AD_INSTR_LDNF1SH },
/* 1 0 1 0 */ { "ldnf1w", AD_INSTR_LDNF1W },
/* 1 0 1 1 */ { "ldnf1w", AD_INSTR_LDNF1W },
/* 1 1 0 0 */ { "ld1nfsb", AD_INSTR_LDNF1SB },
/* 1 1 0 1 */ { "ld1nfsb", AD_INSTR_LDNF1SB },
/* 1 1 1 0 */ { "ld1nfsb", AD_INSTR_LDNF1SB },
/* 1 1 1 1 */ { "ld1nfd", AD_INSTR_LDNF1D },
};

static const struct itab ldff1_tab[] = {
/* 0 0 0 0 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 0 0 0 1 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 0 0 1 0 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 0 0 1 1 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 0 1 0 0 */ { "ldff1sw", AD_INSTR_LDFF1SW },
/* 0 1 0 1 */ { "ldff1h", AD_INSTR_LDFF1H },
/* 0 1 1 0 */ { "ldff1h", AD_INSTR_LDFF1H },
/* 0 1 1 1 */ { "ldff1h", AD_INSTR_LDFF1H },
/* 1 0 0 0 */ { "ldff1sh", AD_INSTR_LDFF1SH },
/* 1 0 0 1 */ { "ldff1sh", AD_INSTR_LDFF1SH },
/* 1 0 1 0 */ { "ldff1w", AD_INSTR_LDFF1W },
/* 1 0 1 1 */ { "ldff1w", AD_INSTR_LDFF1W },
/* 1 1 0 0 */ { "ldff1sb", AD_INSTR_LDFF1SB },
/* 1 1 0 1 */ { "ldff1sb", AD_INSTR_LDFF1SB },
/* 1 1 1 0 */ { "ldff1sb", AD_INSTR_LDFF1SB },
/* 1 1 1 1 */ { "ldff1d", AD_INSTR_LDFF1D },
};

static int op05(struct instruction *i, struct ad_insn *out)
{
  // SVE Memory - Contiguous Load - page 2815
  unsigned op0 = bits(i->opcode, 21, 22);
  unsigned op1 = bits(i->opcode, 20, 20);
  unsigned op2 = bits(i->opcode, 13, 15);

  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Rn = bits(i->opcode, 5, 9);
  unsigned Zt = bits(i->opcode, 0, 4);
  unsigned msz = bits(i->opcode, 23, 24);
  int sz = get_sz(msz);

  if ( !op0 && !op1 && (7 == op2) )
  {
    // SVE contiguous non-temporal load (scalar plus immediate) - page 2815
    unsigned imm4 = bits(i->opcode, 16, 19);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

    SET_INSTR_ID(out, ldn_tab2[msz].instr_id);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ldn_tab2[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
    return 0;
  }
  if ( !op0 && (6 == op2) )
  {
    // SVE contiguous non-temporal load (scalar plus scalar) - page 2816
    unsigned Rm = bits(i->opcode, 16, 20);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
    SET_INSTR_ID(out, ldn_tab2[msz].instr_id);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ldn_tab2[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  if ( op0 && !op1 && (7 == op2) )
  {
    // SVE load multiple structures (scalar plus immediate) - page 2816
    unsigned opc = bits(i->opcode, 21, 22);
    unsigned imm4 = bits(i->opcode, 16, 19);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    unsigned idx = (msz << 2) | opc;

    if ( NULL == ld2_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, ld2_tab[idx].instr_id);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld2_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
    return 0;
  }
  if ( op0 && (6 == op2) )
  {
    // SVE load multiple structures (scalar plus scalar) - page 2816
    unsigned Rm = bits(i->opcode, 16, 20);
    unsigned opc = bits(i->opcode, 21, 22);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
    unsigned idx = (msz << 2) | opc;
    if ( NULL == ld2_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, ld2_tab[idx].instr_id);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ld2_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  if ( !op1 && (1 == op2) )
  {
    // SVE load and broadcast quadword (scalar plus immediate) - page 2817
    unsigned ssz = bits(i->opcode, 21, 22);
    unsigned imm4 = bits(i->opcode, 16, 19);
    unsigned idx = (msz << 2) | ssz;
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    if ( NULL == ld1r_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, ld1r_tab[idx].instr_id);
    ADD_FIELD(out, msz);
    ADD_FIELD(out, ssz);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1r_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
    return 0;
  }
  if ( !op1 && (5 == op2) )
  {
    // SVE contiguous load (scalar plus immediate) - page 2817
    unsigned dtype = bits(i->opcode, 21, 24);
    int sz = get_sz(dtype & 3);
    unsigned imm4 = bits(i->opcode, 16, 19);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);

    SET_INSTR_ID(out, ld1_tab5[dtype].instr_id);
    ADD_FIELD(out, dtype);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab5[dtype].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
    return 0;
  }
  if ( op1 && (5 == op2) )
  {
    // SVE contiguous non-fault load (scalar plus immediate) - page 2818
    unsigned dtype = bits(i->opcode, 21, 24);
    int sz = get_sz(dtype & 3);
    unsigned imm4 = bits(i->opcode, 16, 19);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    SET_INSTR_ID(out, ldnf_ftab[dtype].instr_id);
    ADD_FIELD(out, dtype);
    ADD_FIELD(out, imm4);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ldnf_ftab[dtype].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
    return 0;
  }
  if ( !op2 )
  {
    // SVE load and broadcast quadword (scalar plus scalar) - page 2818
    unsigned ssz = bits(i->opcode, 21, 22);
    unsigned idx = (msz << 2) | ssz;
    unsigned Rm = bits(i->opcode, 16, 20);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

    if ( NULL == ld1r_tab[idx].instr_s )
      return 1;

    SET_INSTR_ID(out, ld1r_tab[idx].instr_id);
    ADD_FIELD(out, msz);
    ADD_FIELD(out, ssz);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ld1r_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  if ( 2 == op2 )
  {
    // SVE contiguous load (scalar plus scalar) - page 2818
    unsigned dtype = bits(i->opcode, 21, 24);
    int sz = get_sz(dtype & 3);
    unsigned Rm = bits(i->opcode, 16, 20);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

    SET_INSTR_ID(out, ld1_tab5[dtype].instr_id);
    ADD_FIELD(out, dtype);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ld1_tab5[dtype].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  if ( 3 == op2 )
  {
    // SVE contiguous first-fault load (scalar plus scalar) - page 2819
    unsigned dtype = bits(i->opcode, 21, 24);
    int sz = get_sz(dtype & 3);
    unsigned Rm = bits(i->opcode, 16, 20);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);

    SET_INSTR_ID(out, ldff1_tab[dtype].instr_id);
    ADD_FIELD(out, dtype);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ldff1_tab[dtype].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
    return 0;
  }
  return 1;
}

static const struct itab ld1_tab6[] = {
/* 00 0 0 */ { NULL, AD_NONE },
/* 00 0 1 */ { NULL, AD_NONE },
/* 00 1 0 */ { NULL, AD_NONE },
/* 00 1 1 */ { NULL, AD_NONE },
/* 01 0 0 */ { "ld1sh", AD_INSTR_LD1SH },
/* 01 0 1 */ { "ld1ffsh", AD_INSTR_LDFF1SH },
/* 01 1 0 */ { "ld1h", AD_INSTR_LD1H },
/* 01 1 1 */ { "ld1ffh", AD_INSTR_LDFF1H },
/* 10 0 0 */ { "ld1sw", AD_INSTR_LD1SW },
/* 10 0 1 */ { "ld1ffsw", AD_INSTR_LDFF1SW },
/* 10 1 0 */ { "ld1w", AD_INSTR_LD1W },
/* 10 1 1 */ { "ld1ffw", AD_INSTR_LDFF1W },
/* 11 0 0 */ { NULL, AD_NONE },
/* 11 0 1 */ { NULL, AD_NONE },
/* 11 1 0 */ { "ld1d", AD_INSTR_LD1D },
/* 11 1 1 */ { "ldff1d", AD_INSTR_LDFF1D },
};

static const struct itab ldn_tab3[] = {
/* 0 0 0 */ { "ldnt1sb", AD_INSTR_LDNT1SB },
/* 0 0 1 */ { "ldnt1b", AD_INSTR_LDNT1B },
/* 0 1 0 */ { "ldnt1sh", AD_INSTR_LDNT1SH },
/* 0 1 1 */ { "ldnt1h", AD_INSTR_LDNT1H },
/* 1 0 0 */ { "ldnt1sw", AD_INSTR_LDNT1SW },
/* 1 0 1 */ { "ldnt1w", AD_INSTR_LDNT1W },
/* 1 1 0 */ { NULL, AD_NONE },
/* 1 1 1 */ { "ldnt1d", AD_INSTR_LDNT1D },
};

static const struct itab ld1_tab7[] = {
/* 00 0 0 */ { "ld1sb", AD_INSTR_LD1SB },
/* 00 0 1 */ { "ldff1sb", AD_INSTR_LDFF1SB },
/* 00 1 0 */ { "ld1b", AD_INSTR_LD1B },
/* 00 1 1 */ { "ldff1b", AD_INSTR_LDFF1B },
/* 01 0 0 */ { "ld1sh", AD_INSTR_LD1SH },
/* 01 0 1 */ { "ldff1sh", AD_INSTR_LDFF1SH },
/* 01 1 0 */ { "ld1h", AD_INSTR_LD1H },
/* 01 1 1 */ { "ldff1h", AD_INSTR_LDFF1H },
/* 10 0 0 */ { "ld1sw", AD_INSTR_LD1SW },
/* 10 0 1 */ { "ldff1sw", AD_INSTR_LDFF1SW },
/* 10 1 0 */ { "ld1w", AD_INSTR_LD1W },
/* 10 1 1 */ { "ldff1w", AD_INSTR_LDFF1W },
/* 11 0 0 */ { NULL, AD_NONE },
/* 11 0 1 */ { NULL, AD_NONE },
/* 11 1 0 */ { "ld1d", AD_INSTR_LD1D },
/* 11 1 1 */ { "ldff1d", AD_INSTR_LDFF1D },
};

static int op06(struct instruction *i, struct ad_insn *out)
{
  // SVE Memory - 64-bit Gather - page 
  unsigned op3 = bits(i->opcode, 4, 4);
  unsigned op2 = bits(i->opcode, 13, 15);
  unsigned op1 = bits(i->opcode, 21, 22);
  unsigned op0 = bits(i->opcode, 23, 24);

  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Rn = bits(i->opcode, 5, 9);
  unsigned Zt = bits(i->opcode, 0, 4);
  unsigned prfop = bits(i->opcode, 0, 3);
  unsigned msz = bits(i->opcode, 23, 24);
  unsigned xs = bits(i->opcode, 22, 22);

  if ( !op0 )
  {
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    msz = bits(i->opcode, 13, 14);
    if ( (3 == op1) && (1 == (op2 >> 2)) && !op3 )
    {
      // SVE 64-bit gather prefetch (scalar plus 64-bit scaled offsets) - page 2820
      SET_INSTR_ID(out, prf_tab[msz].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, prfop);

      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      if ( prfop_name[prfop] != NULL )
        concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      else
        concat(DECODE_STR(out), "%s #%x, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( (op1 & 1) && !(op2 >> 2) && !op3 ) 
    {
      // SVE 64-bit gather prefetch (scalar plus unpacked 32-bit scaled offsets) - page 2821
      SET_INSTR_ID(out, prf_tab[msz].instr_id);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, prfop);

      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      if ( prfop_name[prfop] != NULL )
        concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      else
        concat(DECODE_STR(out), "%s #%x, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
  }
  if ( op0 && (3 == op1) && (1 == (op2 >> 2)) )
  {
    // SVE 64-bit gather load (scalar plus 64-bit scaled offsets) - page 2821
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    msz = bits(i->opcode, 13, 14);
    SET_INSTR_ID(out, prf_tab[msz].instr_id);
    ADD_FIELD(out, xs);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, msz);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, prfop);

    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
    if ( prfop_name[prfop] != NULL )
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
    else
      concat(DECODE_STR(out), "%s #%x, %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
    return 0;
  }
  if ( op0 && (op1 & 1) && !(op2 >> 2) )
  {
    // SVE 64-bit gather load (scalar plus 32-bit unpacked scaled offsets) - page 2821
    unsigned U = bits(i->opcode, 14, 14);
    unsigned ff = bits(i->opcode, 13, 13);
    unsigned opc = bits(i->opcode, 23, 24);
    unsigned idx = (opc << 2) | (U << 1) | ff;
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    if ( NULL == ld1_tab6[idx].instr_s )
      return 1;
    SET_INSTR_ID(out, ld1_tab6[idx].instr_id);
    ADD_FIELD(out, opc);
    ADD_FIELD(out, xs);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", ld1_tab6[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
    return 0;
  }
  if ( !op1 && (7 == op2) && !op3 )
  {
    // SVE 64-bit gather prefetch (vector plus immediate) - page 2822
    unsigned imm5 = bits(i->opcode, 16, 20);
    unsigned Zn = Rn;

    SET_INSTR_ID(out, prf_tab[msz].instr_id);
    ADD_FIELD(out, imm5);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, prfop);

    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&prfop);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
    if ( prfop_name[prfop] != NULL )
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", prf_tab[msz].instr_s, prfop_name[prfop], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    else
      concat(DECODE_STR(out), "%s #%x, %s, %s, #%x", prf_tab[msz].instr_s, prfop, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    return 0;
  }
  if ( !op1 && (4 == (op2 & 5)) )
  {
    // SVE2 64-bit gather non-temporal load (scalar plus unpacked 32-bit unscaled offsets) - page 2822
    unsigned U = bits(i->opcode, 14, 14);
    unsigned Zn = Rn;
    unsigned Rm = Zm;
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    unsigned idx = (msz << 1) | U;
    if ( NULL == ldn_tab3[idx].instr_s )
      return 1;
    SET_INSTR_ID(out, ldn_tab3[idx].instr_id);
    ADD_FIELD(out, Rm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    concat(DECODE_STR(out), "%s %s, %s, %s, %s", ldn_tab3[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], Rm_s);
    return 0;
  }
  if ( (1 == op1) && (4 & op2) )
  {
    // SVE 64-bit gather load (vector plus immediate) - page 2822
    unsigned U = bits(i->opcode, 14, 14);
    unsigned ff = bits(i->opcode, 13, 13);
    unsigned Zn = Rn;
    unsigned imm5 = bits(i->opcode, 16, 20);
    unsigned idx = (msz << 2) | (U << 1) | ff;
    if ( NULL == ld1_tab7[idx].instr_s )
      return 1;
    SET_INSTR_ID(out, ld1_tab7[idx].instr_id);
    ADD_FIELD(out, imm5);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Zn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
    concat(DECODE_STR(out), "%s %s, %s, %s, #%x", ld1_tab7[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
    return 0;
  }
  if ( (2 == op1) && (4 & op2) )
  {
    // SVE 64-bit gather load (scalar plus 64-bit unscaled offsets) - page 2823
    unsigned U = bits(i->opcode, 14, 14);
    unsigned ff = bits(i->opcode, 13, 13);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    unsigned idx = (msz << 2) | (U << 1) | ff;
    if ( NULL == ld1_tab7[idx].instr_s )
      return 1;
    SET_INSTR_ID(out, ld1_tab7[idx].instr_id);
    ADD_FIELD(out, xs);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", ld1_tab7[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
    return 0;
  }
  if ( !(op1 & 1) && !(4 & op2) )
  {
    // SVE 64-bit gather load (scalar plus unpacked 32-bit unscaled offsets) - page 2823
    unsigned U = bits(i->opcode, 14, 14);
    unsigned ff = bits(i->opcode, 13, 13);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    unsigned idx = (msz << 2) | (U << 1) | ff;
    if ( NULL == ld1_tab7[idx].instr_s )
      return 1;
    SET_INSTR_ID(out, ld1_tab7[idx].instr_id);
    ADD_FIELD(out, xs);
    ADD_FIELD(out, Zm);
    ADD_FIELD(out, Pg);
    ADD_FIELD(out, Rn);
    ADD_FIELD(out, Zt);

    ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
    ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
    ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
    ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
    concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", ld1_tab7[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
    return 0;
  }
  return 1;
}

static const struct itab st1_ftab[] = {
/* 0 0 */ { "st1b", AD_INSTR_ST1B },
/* 0 1 */ { "st1h", AD_INSTR_ST1H },
/* 1 0 */ { "st1w", AD_INSTR_ST1W },
/* 1 1 */ { "st1d", AD_INSTR_ST1D },
};

static const struct itab st1_tab2[] = {
/* 0 0 */ { NULL, AD_NONE },
/* 0 1 */ { "st1h", AD_INSTR_ST1H },
/* 1 0 */ { "st1w", AD_INSTR_ST1W },
/* 1 1 */ { "st1d", AD_INSTR_ST1D },
};

static const struct itab st1_tab3[] = {
/* 0 0 */ { "st1b", AD_INSTR_ST1B },
/* 0 1 */ { "st1h", AD_INSTR_ST1H },
/* 1 0 */ { "st1w", AD_INSTR_ST1W },
/* 1 1 */ { NULL, AD_NONE },
};

static const struct itab st1_tab4[] = {
/* 0 0 */ { NULL, AD_NONE },
/* 0 1 */ { "st1h", AD_INSTR_ST1H },
/* 1 0 */ { "st1w", AD_INSTR_ST1W },
/* 1 1 */ { NULL, AD_NONE },
};

static const struct itab stnt1_ftab[] = {
/* 0 0 */ { "stnt1b", AD_INSTR_STNT1B },
/* 0 1 */ { "stnt1h", AD_INSTR_STNT1H },
/* 1 0 */ { "stnt1w", AD_INSTR_STNT1W },
/* 1 1 */ { "stnt1d", AD_INSTR_STNT1D },
};

static const struct itab stN_tab[] = {
/* 00 0 0 */ { NULL, AD_NONE },
/* 00 0 1 */ { "st2b", AD_INSTR_ST2B },
/* 00 1 0 */ { "st3b", AD_INSTR_ST3B },
/* 00 1 1 */ { "st4b", AD_INSTR_ST4B },
/* 01 0 0 */ { NULL, AD_NONE },
/* 01 0 1 */ { "st2h", AD_INSTR_ST2H },
/* 01 1 0 */ { "st3h", AD_INSTR_ST3H },
/* 01 1 1 */ { "st4h", AD_INSTR_ST4H },
/* 10 0 0 */ { NULL, AD_NONE },
/* 10 0 1 */ { "st2w", AD_INSTR_ST2W },
/* 10 1 0 */ { "st3w", AD_INSTR_ST3W },
/* 10 1 1 */ { "st4w", AD_INSTR_ST4W },
/* 11 0 0 */ { NULL, AD_NONE },
/* 11 0 1 */ { "st2d", AD_INSTR_ST2D },
/* 11 1 0 */ { "st3d", AD_INSTR_ST3D },
/* 11 1 1 */ { "st4d", AD_INSTR_ST4D },
};

static int op07(struct instruction *i, struct ad_insn *out, unsigned op3)
{
  unsigned Zm = bits(i->opcode, 16, 20);
  unsigned Pg = bits(i->opcode, 10, 12);
  unsigned Rn = bits(i->opcode, 5, 9);
  unsigned Zt = bits(i->opcode, 0, 4);
  unsigned op0 = bits(i->opcode, 21, 22);
  // 0x0xxx
  if ( !(op3 & 0x28) )
  {
    // SVE Memory - Contiguous Store and Unsized Contiguous - page 2824
    unsigned op1 = bits(i->opcode, 14, 14);
    unsigned op2 = bits(i->opcode, 4, 4);
    op0 = bits(i->opcode, 22, 24);
    if ( 3 == op0 && !op1 && !op1 )
    {
      // str (predicate) - page 2491
      unsigned imm9h = bits(i->opcode, 16, 21);
      unsigned imm9l = bits(i->opcode, 10, 12);
      unsigned Pt = bits(i->opcode, 0, 3);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned imm = (imm9h << 3) | imm9l;
      SET_INSTR_ID(out, AD_INSTR_STR);

      ADD_FIELD(out, imm9h);
      ADD_FIELD(out, imm9l);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Pt);

      ADD_ZREG_OPERAND(out, Pt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "str %s, %s, #%x", AD_RTBL_PG_128[Pt], Rn_s, imm);
      return 0;
    }
    if ( 3 == op0 && op1 )
    {
      // str (vector) - page 2492
      unsigned imm9h = bits(i->opcode, 16, 21);
      unsigned imm9l = bits(i->opcode, 10, 12);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned imm = (imm9h << 3) | imm9l;
      SET_INSTR_ID(out, AD_INSTR_STR);

      ADD_FIELD(out, imm9h);
      ADD_FIELD(out, imm9l);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm);
      concat(DECODE_STR(out), "str %s, %s, #%x", AD_RTBL_Z_128[Zt], Rn_s, imm);
      return 0;
    }
    if ( (3 != op0) && op1 )
    {
      // SVE contiguous store (scalar plus scalar) - page 2824
      const char *instr_s = NULL;
      unsigned opc = bits(i->opcode, 22, 24);
      unsigned o2 = bits(i->opcode, 21, 21);
      unsigned size = bits(i->opcode, 21, 22);
      int sz = get_sz(size);
      unsigned Rm = Zm;
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
      if ( 3 == opc )
        return 1;
      if ( !(opc >> 1) )
      {
        instr_s = "st1b";
        SET_INSTR_ID(out, AD_INSTR_ST1B);
      } else if ( 1 == (opc >> 1) )
      {
        instr_s = "st1h";
        SET_INSTR_ID(out, AD_INSTR_ST1H);
      } else if ( 2 == (opc >> 1) )
      {
        instr_s = "st1w";
        SET_INSTR_ID(out, AD_INSTR_ST1W);
      } else if ( 7 == opc && o2 )
      {
        instr_s = "st1d";
        SET_INSTR_ID(out, AD_INSTR_ST1D);
      } else
        return 1;
      ADD_FIELD(out, size);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
      return 0;
    }
    return 1;
  }
  // 0x1xxx
  if ( 1 == ((op3 >> 3) & 5) )
  {
    unsigned Rm = Zm;
    unsigned Zn = Rn;
    const char *Rm_s = GET_GEN_REG(AD_RTBL_GEN_64, Rm, NO_PREFER_ZR);
    unsigned msz = bits(i->opcode, 23, 24);
    // SVE Memory - Non-temporal and Multi-register Store - page 2823
    unsigned op1 = bits(i->opcode, 14, 14);
    if ( !op0 && !op1 )
    {
      // SVE2 64-bit scatter non-temporal store (vector plus scalar) - page 2825
      SET_INSTR_ID(out, stnt1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", stnt1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], Rm_s);
      return 0;
    }
    if ( !op0 && op1 )
    {
      // SVE contiguous non-temporal store (scalar plus scalar) - page 2825
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      SET_INSTR_ID(out, stnt1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", stnt1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
      return 0;
    }
    if ( (2 == op0) && !op1 )
    {
      // SVE2 32-bit scatter non-temporal store (vector plus scalar) - page 2825
      if ( 3 == msz )
        return 1;
      SET_INSTR_ID(out, stnt1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_REG_OPERAND(out, Rm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", stnt1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], Rm_s);
      return 0;
    }
    if ( op0 && op1 )
    {
      // SVE store multiple structures (scalar plus scalar) - page 2825
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned opc = bits(i->opcode, 21, 22);
      unsigned idx = (msz << 2) | opc;
      if ( NULL == stN_tab[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, stN_tab[idx].instr_id);
      ADD_FIELD(out, Rm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_REG_OPERAND(out, Rm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      concat(DECODE_STR(out), "%s %s, %s, %s, %s", stN_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, Rm_s);
      return 0;
    }
    return 1;
  }
  // 1x0xxx
  if ( 4 == ((op3 >> 3) & 5) )
  {
    // SVE Memory - Scatter with Optional Sign Extend - page 2827
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned xs = bits(i->opcode, 14, 14);
    const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
    if ( !op0 )
    {
      // SVE 64-bit scatter store (scalar plus 64-bit unscaled offsets) - page 2826
      SET_INSTR_ID(out, st1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( 1 == op0 )
    {
      // SVE 64-bit scatter store (scalar plus unpacked 32-bit scaled offsets) - page 2826
      if ( NULL == st1_tab2[msz].instr_s )
        return 1;
      SET_INSTR_ID(out, st1_tab2[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_tab2[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE 32-bit scatter store (scalar plus 32-bit unscaled offsets) - page 2827
      if ( NULL == st1_tab3[msz].instr_s )
        return 1;
      SET_INSTR_ID(out, st1_tab3[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_tab3[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE 32-bit scatter store (scalar plus 32-bit scaled offsets) - page 2827
      if ( NULL == st1_tab4[msz].instr_s )
        return 1;
      SET_INSTR_ID(out, st1_tab4[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_tab4[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    return 1;
  }
  if ( 5 == (op3 >> 3) )
  {
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned xs = bits(i->opcode, 14, 14);
    // SVE Memory - Scatter - page 2827
    if ( !op0 )
    {
      // SVE 64-bit scatter store (scalar plus 64-bit unscaled offsets) - page 2827
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      SET_INSTR_ID(out, st1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, xs);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( 1 == op0 )
    {
      // SVE 64-bit scatter store (scalar plus 64-bit scaled offsets) - page 2828
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      if ( NULL == st1_tab2[msz].instr_s )
        return 1;
      SET_INSTR_ID(out, st1_tab2[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, Zm);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_ZREG_OPERAND(out, Zm, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&xs);
      concat(DECODE_STR(out), "%s %s, %s, %s, %s, #%x", st1_tab2[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, AD_RTBL_Z_128[Zm], xs);
      return 0;
    }
    if ( 2 == op0 )
    {
      // SVE 64-bit scatter store (vector plus immediate) - page 2828
      unsigned imm5 = bits(i->opcode, 16, 20);
      unsigned Zn = Rn;
      SET_INSTR_ID(out, st1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, imm5);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", st1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
      return 0;
    }
    if ( 3 == op0 )
    {
      // SVE 64-bit scatter store (vector plus immediate) - page 2828
      unsigned imm5 = bits(i->opcode, 16, 20);
      unsigned Zn = Rn;
      if ( NULL == st1_tab3[msz].instr_s )
        return 1;
      SET_INSTR_ID(out, st1_tab3[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, imm5);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Zn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_ZREG_OPERAND(out, Zn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm5);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", st1_tab3[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], imm5);
      return 0;
    }
    return 1;
  }
  if ( 7 == (op3 >> 3) )
  {
    // SVE Memory - Contiguous Store with Immediate Offset - page 2829
    unsigned op1 = bits(i->opcode, 20, 20);
    unsigned msz = bits(i->opcode, 23, 24);
    unsigned imm4 = bits(i->opcode, 16, 19);
    if ( !op0 && op1 )
    {
      // SVE contiguous non-temporal store (scalar plus immediate) - page 2829
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      SET_INSTR_ID(out, stnt1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _32_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", stnt1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
      return 0;
    }
    if ( op0 && op1 )
    {
      // SVE store multiple structures (scalar plus immediate) - page 2829
      unsigned opc = bits(i->opcode, 21, 22);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      unsigned idx = (msz << 2) | opc;
      if ( NULL == stN_tab[idx].instr_s )
        return 1;
      SET_INSTR_ID(out, stN_tab[idx].instr_id);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, _64_BIT, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", stN_tab[idx].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
      return 0;
    }
    if ( !op1 )
    {
      // SVE contiguous store (scalar plus immediate) - page 2829
      unsigned size = bits(i->opcode, 21, 22);
      int sz = get_sz(size);
      const char *Rn_s = GET_GEN_REG(AD_RTBL_GEN_64, Rn, NO_PREFER_ZR);
      SET_INSTR_ID(out, st1_ftab[msz].instr_id);
      ADD_FIELD(out, msz);
      ADD_FIELD(out, size);
      ADD_FIELD(out, imm4);
      ADD_FIELD(out, Pg);
      ADD_FIELD(out, Rn);
      ADD_FIELD(out, Zt);

      ADD_ZREG_OPERAND(out, Zt, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      ADD_ZREG_OPERAND(out, Pg, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_PG_128, 3);
      ADD_REG_OPERAND(out, Rn, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), _RTBL(AD_RTBL_GEN_64));
      ADD_IMM_OPERAND(out, AD_IMM_INT, *(int *)&imm4);
      concat(DECODE_STR(out), "%s %s, %s, %s, #%x", st1_ftab[msz].instr_s, AD_RTBL_Z_128[Zt], AD_RTBL_PG_128[Pg], Rn_s, imm4);
      return 0;
    }
    return 1;
  }
  return 1;
}

int Disassemble_SVE(struct instruction *i, struct ad_insn *out)
{
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
          return op00_op10_op20(i, out, op3);
        else
          return op00_op10_op21(i, out, op3);
      }
      if ( op1 & 2 )
      {
        if ( !(op2 >> 3) )
          return op00_op11_op20(i, out, op3);
        if ( 1 == (op2 >> 3) )
          return op00_op11_op21(i, out, op3);
        if ( 1 == (op2 >> 4) )
          return op00_op11_op25(i, out, op3);
      }
      if ( (op1 == 2) && (1 == (op2 >> 4)) )
        return op00_op12_op25(i, out, op3);
      if ( (op1 == 3) && (1 == (op2 >> 4)) )
        return op00_op13_op25(i, out, op3);
      return 1;
    }

    if ( 1 == op0 )
    {
      // 001 0x 0xxxx
      if ( !(op1 >> 1) && !(op2 >> 4) )
        return op01_op0_op20(i, out, op3);
      // 001 0x 1xxxx
      if ( !(op1 >> 1) && (1 == (op2 >> 4)) )
        return op01_op0_op21(i, out, op3);
      // 001 1x 0xxxx
      if ( (op1 >> 1) && (0 == (op2 >> 4)) )
        return op1_op1_op20(i, out, op3);
      // 001 1x 00xxx
      if ( (op1 >> 1) && (0 == (op2 >> 3)) )
        return op1_op1_op30(i, out, op3);
      // 001 1x 01xxx
      if ( (op1 >> 1) && (1 == (op2 >> 3)) )
        return op1_op1_op31(i, out, op3);
      // 001 1x 1xxxx
      if ( (op1 >> 1) && (1 == (op2 >> 4)) )
        return op1_op1_op41(i, out, op3);
      // 001 1x 100xx
      if ( (op1 >> 1) && (4 == (op2 >> 2)) )
        return op1_op1_op42(i, out, op3);
      // 001 1x 101xx
      if ( (op1 >> 1) && (5 == (op2 >> 2)) )
        return op1_op1_op52(i, out, op3);
      return 1;
    }

    if ( 2 == op0 )
    {
      // 010 0x 0xxxx
      if ( !(op1 >> 1) && !(op2 >> 4) )
        return op02_op0_op20(i, out, op3);
      // 010 0x 1xxxx
      if ( !(op1  >> 1) && (1 == (op2 >> 4)) )
        return op02_op0_op21(i, out, op3);
      // 010 1x 0xxxx
      if ( (op1 >> 1) && !(op2 >> 4) )
        return op02_op1_op20(i, out, op3);
      // 010 1x 1xxxx
      if ( (op1 >> 1) && (1 == (op2 >> 4)) )
        return op02_op1_op21(i, out, op3);
      return 1;
    }

    if ( 3 == op0 )
    {
      // 011 0x 00000
      if ( !(op1 >> 1) && !op2 )
        return op03_op0_op20(i, out, op3);
      // 011 0x 0010x
      if ( !(op1 >> 1) && (2 == (op2 >> 1)) )
        return op03_op0_op21(i, out, op3);
      // 011 0x 010xx
      if ( !(op1 >> 1) && (2 == (op2 >> 2)) )
        return op03_op0_op22(i, out, op3);
      // 011 0x 1xxxx
      if ( !(op1 >> 1) && (1 == (op2 >> 4)) )
        return op03_op0_op14(i, out, op3);
      // 011 1x 0xxxx
      if ( (op1 >> 1) && !(op2 >> 4) )
        return op03_op1_op40(i, out, op3);
      // 011 1x 000xx
      if ( (op1 >> 1) && !(op2 >> 2) )
        return op03_op1_op20(i, out, op3);
      // 011 1x 001xx
      if ( (op1 >> 1) && (1 == (op2 >> 2)) )
        return op03_op1_op21(i, out, op3);
      // 011 1x 010xx
      if ( (op1 >> 1) && (2 == (op2 >> 2)) )
        return op03_op1_op22(i, out, op3);
      // 011 1x 011xx
      if ( (op1 >> 1) && (3 == (op2 >> 2)) )
        return op03_op1_op23(i, out, op3);
      // 011 1x 1xxxx
      if ( (op1 >> 1) && (1 == (op2 >> 4)) )
        return op03_op1_op14(i, out, op3);
      return 1;
    }

    if ( 4 == op0 )
      return op04(i, out);

    if ( 5 == op0 )
      return op05(i, out);

    if ( 6 == op0 )
      return op06(i, out);

    if ( 7 == op0 )
      return op07(i, out, op3);

    return 1;
}
