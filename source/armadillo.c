#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adefs.h"
#include "bits.h"
#include "common.h"
#include "instruction.h"
#include "strext.h"

#include "BranchExcSys.h"
#include "DataProcessingImmediate.h"
#include "DataProcessingFloatingPoint.h"
#include "DataProcessingRegister.h"
#include "LoadsAndStores.h"

static int _ArmadilloDisassemble(struct instruction *i, struct ad_insn *out)
{

    unsigned op0 = bits(i->opcode, 25, 28);

    if(op0 == 0){
        unsigned op1 = bits(i->opcode, 16, 24);
        out->group = AD_G_Reserved;

        if(op1 != 0)
            return 1;
        else
        {
        unsigned imm16 = bits(i->opcode, 0, 15);

        ADD_FIELD(out, op0);
        ADD_FIELD(out, op1);
        ADD_FIELD(out, imm16);

        ADD_IMM_OPERAND(out, AD_IMM_UINT, *(unsigned *)&imm16);

        concat(DECODE_STR(out), "udf #%#x", imm16);

        SET_INSTR_ID(out, AD_INSTR_UDF);
        }
        return 0;
    }
    else if(op0 > 0 && op0 <= 3){
        return 1;
    }
    else if((op0 >> 1) == 4){
        out->group = AD_G_DataProcessingImmediate;
        return DataProcessingImmediateDisassemble(i, out);
    }
    else if((op0 >> 1) == 5){
        out->group = AD_G_BranchExcSys;
        return BranchExcSysDisassemble(i, out);
    }
    else if((op0 & ~10) == 4){
        out->group = AD_G_LoadsAndStores;
        return LoadsAndStoresDisassemble(i, out);
    }
    else if((op0 & ~8) == 5){
        out->group = AD_G_DataProcessingRegister;
        return DataProcessingRegisterDisassemble(i, out);
    }
    else if((op0 & ~8) == 7){
        out->group = AD_G_DataProcessingFloatingPoint;
        return DataProcessingFloatingPointDisassemble(i, out);
    }

    return 0;
}

void armadillo_init(struct ad_insn *dis)
{
  dis->decoded[0] = 0;

  dis->group = AD_NONE;
  dis->instr_id = AD_NONE;

  memset(dis->fields, 0, sizeof(dis->fields));
  dis->num_fields = 0;

  memset(dis->operands, 0, sizeof(dis->operands));
  dis->num_operands = 0;

  dis->cc = AD_NONE;
}

int ArmadilloDisassemble(unsigned int opcode, uint64 PC, struct ad_insn *out)
{
    if( NULL == out )
        return 1;
    else
    {
      struct instruction i = { opcode, PC };
      int result;
      armadillo_init(out);

      result = _ArmadilloDisassemble(&i, out);

      if (result)
        concat(DECODE_STR(out), ".long %#x", i.opcode);
      return result;
    }
}
