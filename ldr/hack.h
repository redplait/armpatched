#pragma once
#include "pe_file.h"
#include "../source/armadillo.h"

// register scratchpad class
#ifdef _WIN64
typedef LONGLONG  reg64_t;
#else
typedef long  reg64_t;
#endif /* _WIN64 */

class regs_pad
{
  public:
   regs_pad()
   {
     memset(m_regs, 0, sizeof(m_regs));
   }
   void reset()
   {
     memset(m_regs, 0, sizeof(m_regs));
   }
   // http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0802a/ADRP.html
   void adrp(int reg, reg64_t val)
   {
     if ( reg >= AD_REG_SP ) // hm
       return;
     m_regs[reg] = val;
   }
   // http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0802a/a64_general_alpha.html
   reg64_t add(int reg1, int reg2, reg64_t val)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( !m_regs[reg2] )
       return 0;
     m_regs[reg1] = m_regs[reg2] + val;
     if ( reg1 != reg2 )
       m_regs[reg2] = 0;
     return m_regs[reg1];
   }
   int ldar(int reg1, int reg2)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     m_regs[reg1] = m_regs[reg2];
     return 1;
   }
   inline reg64_t get(int reg)
   {
     if ( reg >= AD_REG_SP ) // hm
       return 0;
     return m_regs[reg];
   }
   inline void zero(int reg)
   {
     if ( reg >= AD_REG_SP ) // hm
       return;
     m_regs[reg] = 0;
   }
  protected:
   reg64_t m_regs[AD_REG_SP];
};

// some base class for all hacks
class arm64_hack
{
  public:
   arm64_hack(arm64_pe_file *pe, exports_dict *ed);
   virtual ~arm64_hack();   
  protected:
   void fill_lc();
   // disasm methods
   int setup(PBYTE psp)
   {
     PBYTE mz = m_pe->base_addr();
     const one_section *s = m_pe->find_section_rva(psp - mz);
     if ( s == NULL )
       return 0;
     m_psp = psp;
     return 1;
   }
   int disasm();
   int disasm(int state);
    template <typename T>
    int check_jmps(T &graph)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr);
        return 1;
      }
      return 0;
    }
    template <typename T>
    int check_jmps(T &graph, int state)
    {
      PBYTE addr = NULL;
      if ( is_cbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_cbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_tbnz_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      if ( is_bxx_jimm(addr) )
      {
        graph.add(addr, state);
        return 1;
      }
      return 0;
    }
   // variadic methods
   template <typename T>
   int is_xx(T op) const
   {
     return (m_dis.instr_id == op);
   }
   template <typename T, typename... Args>
   int is_xx(T op, Args... args) const
   {
     return (m_dis.instr_id == op) || is_xx(args...);
   }
   template <typename... Args>
   int is_ldrxx(Args... args) const
   {
     if ((m_dis.num_operands == 3) &&
         (m_dis.operands[0].type == AD_OP_REG) &&
         (m_dis.operands[1].type == AD_OP_REG) &&
         (m_dis.operands[2].type == AD_OP_IMM)
        )
       return is_xx(args...);
     return 0;
   }
   // some shortcuts methods
   inline int get_reg(int idx) const
   {
     return m_dis.operands[idx].op_reg.rn;
   }
   int find_first_jmp(PBYTE addr, PBYTE &out);
   int find_first_bl(PBYTE addr, PBYTE &out);
   int find_first_load(PBYTE addr, const char *s_name, PBYTE &out);
   inline int is_ret() const
   {
     return (m_dis.instr_id == AD_INSTR_RET);
   }
   int is_b_jimm(PBYTE &addr) const;
   int is_bxx_jimm(PBYTE &addr) const;
   int is_bl_jimm(PBYTE &addr) const;
   inline int is_bl_reg() const
   {
     return (m_dis.instr_id == AD_INSTR_BLR && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_REG);
   }
   int is_cbnz_jimm(PBYTE &addr) const;
   int is_cbz_jimm(PBYTE &addr) const;
   int is_tbz_jimm(PBYTE &addr) const;
   int is_tbnz_jimm(PBYTE &addr) const;
   inline int is_ldar() const
   {
     return (m_dis.instr_id == AD_INSTR_LDAR && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_REG);
   }
   inline int is_ldar(regs_pad &used_regs) const
   {
     if ( !is_ldar() )
       return 0;
     used_regs.ldar(get_reg(0), get_reg(1));
     return 1;
   }
   int is_adrp() const;
   inline int is_adrp(regs_pad &used_regs) const
   {
     if ( !is_adrp() )
       return 0;
     used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
     return 1;
   }
   int is_add() const;
   int is_ldr() const;
   int is_ldrb() const;
   int is_ldrsb() const;
   int is_str() const;
   inline int is_mov_rimm() const
   {
     return (m_dis.instr_id == AD_INSTR_MOV && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_IMM);
   }
   int in_section(PBYTE addr, const char *sname) const
   {
     ptrdiff_t off = addr - m_pe->base_addr();
     const one_section *s = m_pe->find_section_v(off);
     if ( NULL == s )
       return 0;
     return !strcmp(s->name, sname);
   }
   // load config data
   PBYTE m_cookie;
   PBYTE m_GuardCFCheckFunctionPointer;
   PBYTE m_GuardCFDispatchFunctionPointer;

   // disasm data
   int m_verbose;
   PBYTE m_psp;
   arm64_pe_file *m_pe;
   // pe file data
   exports_dict *m_ed;
   struct ad_insn m_dis;
};
