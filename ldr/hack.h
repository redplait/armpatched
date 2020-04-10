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
   int disasm(int verbose);
   int disasm(int verbose, int state);
   // some shortcuts methods
   inline int get_reg(int idx)
   {
     return m_dis.operands[idx].op_reg.rn;
   }
   int find_first_jmp(PBYTE addr, PBYTE &out, int verbose);
   inline int is_ret() const
   {
     return (m_dis.instr_id == AD_INSTR_RET);
   }
   int is_b_jimm(PBYTE &addr) const;
   int is_bxx_jimm(PBYTE &addr) const;
   int is_bl_jimm(PBYTE &addr) const;
   int is_cbnz_jimm(PBYTE &addr) const;
   int is_cbz_jimm(PBYTE &addr) const;
   int is_tbz_jimm(PBYTE &addr) const;
   int is_tbnz_jimm(PBYTE &addr) const;
   int is_adrp() const;
   int is_add() const;
   int is_ldr() const;
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
   PBYTE m_psp;
   arm64_pe_file *m_pe;
   // pe file data
   exports_dict *m_ed;
   struct ad_insn m_dis;
};
