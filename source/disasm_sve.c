#include <stdio.h>
#include <stdlib.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "utils.h"
#include "strext.h"

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
      ADD_ZREG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Vd]);
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
      ADD_ZREG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Vd]);
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
      ADD_ZREG_OPERAND(out, Vd, sz, NO_PREFER_ZR, _SYSREG(AD_NONE), AD_RTBL_Z_128, 2);
      concat(DECODE_STR(out), "%s %s, %s, %s", instr_s, AD_RTBL_PG_128[Pg], AD_RTBL_Z_128[Zn], AD_RTBL_Z_128[Vd]);
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
    unsigned Zn = bits(i->opcode, 5, 9);
    int sz = get_sz(size);
//    if ( !(op0 & 2) )
  }
  return 1;
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
      }
    }

    return 1;
}