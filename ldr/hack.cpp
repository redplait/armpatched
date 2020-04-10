#include "stdafx.h"
#include "hack.h"

arm64_hack::arm64_hack(arm64_pe_file *pe, exports_dict *ed)
{
  m_pe = pe;
  m_ed = ed;
  m_verbose = 0;
  fill_lc();
}

arm64_hack::~arm64_hack()
{
  if ( m_ed != NULL )
    delete m_ed;
}

void arm64_hack::fill_lc()
{
  m_cookie = NULL;
  m_GuardCFCheckFunctionPointer = m_GuardCFDispatchFunctionPointer = NULL;
  DWORD lc_size = 0;
  PBYTE mz = m_pe->base_addr();
  Prfg_IMAGE_LOAD_CONFIG_DIRECTORY64 lc = (Prfg_IMAGE_LOAD_CONFIG_DIRECTORY64)m_pe->read_load_config(lc_size);
  if ( lc != NULL && lc_size )
  {
    if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerTable) && lc->SecurityCookie )
      m_cookie = mz + (lc->SecurityCookie - m_pe->image_base());
    if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer) && lc->GuardCFCheckFunctionPointer )
      m_GuardCFCheckFunctionPointer = mz + (lc->GuardCFCheckFunctionPointer - m_pe->image_base());
    if ( lc_size >= offsetof(rfg_IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable) && lc->GuardCFDispatchFunctionPointer )
      m_GuardCFDispatchFunctionPointer = mz + (lc->GuardCFDispatchFunctionPointer - m_pe->image_base());
  }
}

// check if current instruction is jmp jimm
int arm64_hack::is_b_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_B && m_dis.cc == AD_NONE && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[0].op_imm.bits;
    return 1;
  } else
    return 0;
}

int arm64_hack::is_tbz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_TBZ && m_dis.num_operands == 3 && m_dis.operands[2].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[2].op_imm.bits;
    return 1;
  }
  return 0;
}

int arm64_hack::is_tbnz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_TBNZ && m_dis.num_operands == 3 && m_dis.operands[2].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[2].op_imm.bits;
    return 1;
  }
  return 0;
}

int arm64_hack::is_cbz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_CBZ && m_dis.num_operands == 2 && m_dis.operands[1].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[1].op_imm.bits;
    return 1;
  }
  return 0;
}

int arm64_hack::is_cbnz_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_CBNZ && m_dis.num_operands == 2 && m_dis.operands[1].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[1].op_imm.bits;
    return 1;
  }
  return 0;
}

int arm64_hack::is_bxx_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_B && m_dis.cc != AD_NONE && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[0].op_imm.bits;
    return 1;
  } else
    return 0;
}

// check if current instruction is call jimm
int arm64_hack::is_bl_jimm(PBYTE &addr) const
{
  if ( m_dis.instr_id == AD_INSTR_BL && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_IMM )
  {
    addr = (PBYTE)m_dis.operands[0].op_imm.bits;
    return 1;
  } else
    return 0;
}

int arm64_hack::is_adrp() const
{
  return (m_dis.instr_id == AD_INSTR_ADRP) && 
         (m_dis.num_operands == 2) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_IMM)
  ;
}

int arm64_hack::is_add() const
{
  return (m_dis.instr_id == AD_INSTR_ADD) && 
         (m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
  ;
}

int arm64_hack::is_ldr() const
{
  return (m_dis.instr_id == AD_INSTR_LDR) && 
         (m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
  ;
}

int arm64_hack::is_str() const
{
  return (m_dis.instr_id == AD_INSTR_STR) && 
         (m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
  ;
}

int arm64_hack::disasm(int state)
{
  if ( !m_pe->is_inside(m_psp + 4) )
    return 0;
  if ( ArmadilloDisassemble(*(PDWORD)m_psp, (ULONGLONG)m_psp, &m_dis) )
    return 0;
  if ( m_verbose )
    printf("%p: %s state %d\n", m_psp, m_dis.decoded, state);
  m_psp += 4;
  if (m_dis.instr_id == AD_INSTR_UDF)
    return 0;
  return 1;
}

int arm64_hack::disasm()
{
  if ( !m_pe->is_inside(m_psp + 4) )
    return 0;
  if ( ArmadilloDisassemble(*(PDWORD)m_psp, (ULONGLONG)m_psp, &m_dis) )
    return 0;
  if ( m_verbose )
    printf("%p: %s\n", m_psp, m_dis.decoded);
  m_psp += 4;
  if (m_dis.instr_id == AD_INSTR_UDF)
    return 0;
  return 1;
}

int arm64_hack::find_first_jmp(PBYTE addr, PBYTE &out)
{
  if ( !setup(addr) )
    return 0;
  for ( DWORD i = 0; i < 10; i++ )
  {
    if ( !disasm() || is_ret() )
      return 0;
    if ( is_b_jimm(out) )
      return 1;
  }
  return 0;
}