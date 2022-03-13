#pragma once
#include "pe_file.h"
#include "../source/armadillo.h"
#include "cf_graph.h"

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
   bool operator<(const regs_pad& s) const
   {
     auto my = std::count_if(m_regs, m_regs + _countof(m_regs), [](const reg64_t &l) -> bool { return l != 0; });
     auto their = std::count_if(s.m_regs, s.m_regs + _countof(s.m_regs), [](const reg64_t &l) -> bool { return l != 0; });
     return (my < their);
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
   reg64_t add2(int reg1, int reg2, reg64_t val)
   {
     if ( (reg1 >= AD_REG_SP) || (reg2 >= AD_REG_SP) ) 
       return 0;
     if ( !m_regs[reg2] )
       return 0;
     m_regs[reg1] = m_regs[reg2] + val;
     return m_regs[reg1];
   }
   reg64_t get_str(int reg2, reg64_t val)
   {
     if (reg2 >= AD_REG_SP)
       return 0;
     if (!m_regs[reg2])
       return 0;
     return m_regs[reg2] + val;
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

// for xrefs search
struct adr_holder
{
  PBYTE addr;
  PBYTE where;
  inline void reset()
  {
    addr = where = NULL;
  }
  adr_holder()
  {
    reset();
  }
};

class xref_finder
{
  public:
   xref_finder()
   {
     reset();
   }
   void reset()
   {
     for ( DWORD i = 0; i < _countof(m_regs); i++ )
       m_regs[i].reset();
     disasm_cnt = adrp_cnt = add_cnt = 0;
   }
   int purge(int i, PBYTE addr)
   {
     if ( NULL == m_regs[i].where )
       return 0;
     // 40 - 10 opcodes
     if ( m_regs[i].where > addr - 40 )
       return 1;
     m_regs[i].reset();
     return 0;
   }
   int find_bl(PBYTE start, DWORD size, PBYTE what, std::list<PBYTE> &);
   // find pair of adrp/add pointing to what
   int find(PBYTE start, DWORD size, PBYTE what, std::list<PBYTE> &);
   PBYTE find(PBYTE start, DWORD size, PBYTE what)
   {
     size &= ~3;
     struct ad_insn dis;
     int reg_n;
     for ( DWORD i = 0; i < size / sizeof(DWORD); i++, start += 4 )
     {
       DWORD val = *(PDWORD)start;
       // check for adrp
       if ( (val & 0x9f000000) == 0x90000000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_ADRP )
           continue;
         adrp_cnt++;
         reg_n = dis.operands[0].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         m_regs[reg_n].addr = (PBYTE)dis.operands[1].op_imm.bits;
         if ( m_regs[reg_n].addr == what )
           return start;
         m_regs[reg_n].where = start;
         continue;
       }
       // check for add
       if ( (val & 0x7f000000) == 0x11000000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_ADD )
           continue;
         add_cnt++;
         reg_n = dis.operands[1].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         if ( !purge(reg_n, start) )
           continue;
         if ( NULL == m_regs[reg_n].addr )
           continue;
         if ( m_regs[reg_n].addr + (reg64_t)dis.operands[2].op_imm.bits == what )
           return start;
       }
     }
     return NULL;
   }
   // find pair of adrp/ldr pointing to what
   int find_ldr(PBYTE start, DWORD size, PBYTE what, std::list<PBYTE> &out_list)
   {
     int res = 0;
     size &= ~3;
     struct ad_insn dis;
     int reg_n;
     for ( DWORD i = 0; i < size / sizeof(DWORD); i++, start += 4 )
     {
       DWORD val = *(PDWORD)start;
       // check for adrp
       if ( (val & 0x9f000000) == 0x90000000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_ADRP )
           continue;
         adrp_cnt++;
         reg_n = dis.operands[0].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         m_regs[reg_n].addr = (PBYTE)dis.operands[1].op_imm.bits;
         m_regs[reg_n].where = start;
         continue;
       }
       // check for ldr
       if ( (val & 0xbfc00000) == 0xb9400000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_LDR )
           continue;
         add_cnt++;
         reg_n = dis.operands[1].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         if ( !purge(reg_n, start) )
           continue;
         if ( NULL == m_regs[reg_n].addr )
           continue;
         if ( m_regs[reg_n].addr + (reg64_t)dis.operands[2].op_imm.bits == what )
         {
           try
           {
             out_list.push_back(start);
             res++;
           } catch(std::bad_alloc)
           { break; }
         }
       }
     }
     return res;
   }
   PBYTE find_ldr(PBYTE start, DWORD size, PBYTE what)
   {
     size &= ~3;
     struct ad_insn dis;
     int reg_n;
     for ( DWORD i = 0; i < size / sizeof(DWORD); i++, start += 4 )
     {
       DWORD val = *(PDWORD)start;
       // check for adrp
       if ( (val & 0x9f000000) == 0x90000000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_ADRP )
           continue;
         adrp_cnt++;
         reg_n = dis.operands[0].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         m_regs[reg_n].addr = (PBYTE)dis.operands[1].op_imm.bits;
         if ( m_regs[reg_n].addr == what )
           return start;
         m_regs[reg_n].where = start;
         continue;
       }
       // check for ldr
       if ( (val & 0xbfc00000) == 0xb9400000 )
       {
         if ( ArmadilloDisassemble(val, (ULONGLONG)start, &dis) )
           continue;
         disasm_cnt++;
         if ( dis.instr_id != AD_INSTR_LDR )
           continue;
         add_cnt++;
         reg_n = dis.operands[1].op_reg.rn;
         if ( reg_n >= AD_REG_SP )
           continue;
         if ( !purge(reg_n, start) )
           continue;
         if ( NULL == m_regs[reg_n].addr )
           continue;
         if ( m_regs[reg_n].addr + (reg64_t)dis.operands[2].op_imm.bits == what )
           return start;
       }
     }
     return NULL;
   }
   DWORD disasm_cnt;
   DWORD adrp_cnt;
   DWORD add_cnt;
  protected:
   adr_holder m_regs[AD_REG_SP];
};

// some base class for all hacks
class arm64_hack
{
  public:
   arm64_hack(arm64_pe_file *pe, exports_dict *ed);
   virtual ~arm64_hack();
   int inside_pdata(PBYTE);
   inline int has_pdata() const
   {
     return (m_pdata_rva != 0) && (m_pdata_size != 0);
   }
   inline const struct export_item *get_exports(size_t &total) const
   {
     if ( m_ed == NULL )
       return NULL;
     total = m_ed->total();
     return m_ed->items();
   }
   inline int in_executable_section(ptrdiff_t off) const
   {
     const one_section *s = m_pe->find_section_rva(off);
     if ( NULL == s )
       return 0;
     return (s->flags & IMAGE_SCN_CNT_CODE) ||
            (s->flags & IMAGE_SCN_MEM_EXECUTE);
   }
   inline int in_executable_section(PBYTE addr) const
   {
     return in_executable_section(addr - m_pe->base_addr());
   }
  protected:
   class save_psp
   {
     public:
      save_psp(arm64_hack &mod)
       : m_mod(mod)
      {
        stored_psp = mod.m_psp;
      }
      ~save_psp()
      {
        m_mod.m_psp = stored_psp;
      }
     protected:
      arm64_hack &m_mod;
      PBYTE stored_psp;
   };
   void init_aux(const char *, PBYTE &aux);
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
    template <typename T, typename S>
    int check_jmps(T &graph, S state)
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
   inline size_t get_reg_size(int idx) const
   {
     return m_dis.operands[idx].op_reg.sz;
   }
   void collect_calls(PBYTE psp, std::set<PBYTE> &, const char *s_name);
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
   inline int is_br_reg() const
   {
     return (m_dis.instr_id == AD_INSTR_BR && m_dis.num_operands == 1 && m_dis.operands[0].type == AD_OP_REG);
   }
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
   inline int is_ldar(regs_pad *used_regs) const
   {
     if ( !is_ldar() )
       return 0;
     used_regs->ldar(get_reg(0), get_reg(1));
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
   int is_adr() const;
   inline int is_adr(regs_pad &used_regs) const
   {
     if ( !is_adr() )
       return 0;
     used_regs.adrp(get_reg(0), m_dis.operands[1].op_imm.bits);
     return 1;
   }
   int is_add() const;
   int is_ldr() const;
   int is_ldrh() const;
   int is_ldr_rr() const;
   int is_ldr_off() const;
   int is_ldrb() const;
   int is_ldrsb() const;
   int is_str() const;
   int is_strb() const;
   int is_strh() const;
   inline int is_cmp_rimm() const
   {
     return (m_dis.instr_id == AD_INSTR_CMP && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_IMM);
   }
   inline int is_mov_rimm() const
   {
     return (m_dis.instr_id == AD_INSTR_MOV && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_IMM);
   }
   inline int is_mov_rr() const
   {
     return (m_dis.instr_id == AD_INSTR_MOV && m_dis.num_operands == 2 && m_dis.operands[0].type == AD_OP_REG && m_dis.operands[1].type == AD_OP_REG);
   }
   inline int is_mov_rr(regs_pad &used_regs) const
   {
     if ( !is_mov_rr() )
       return 0;
     used_regs.ldar(get_reg(0), get_reg(1));
     return 1;
   }
   inline int is_mov_rr(regs_pad *used_regs) const
   {
     if ( !is_mov_rr() )
       return 0;
     used_regs->ldar(get_reg(0), get_reg(1));
     return 1;
   }
   inline int in_section(ptrdiff_t off, const char *sname) const
   {
     const one_section *s = m_pe->find_section_v(off);
     if ( NULL == s )
       return 0;
     return !strcmp(s->name, sname);
   }
   inline int in_section(PBYTE addr, const char *sname) const
   {
     return in_section(addr - m_pe->base_addr(), sname);
   }
   void adjust_pdata();
   PBYTE find_pdata(PBYTE);
   // main method to find simple registered guid - like in rpcrt4_hack.h
   int find_simple_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
   // method to find tlg and reference to it from .data section
   int find_tlg_by_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
   int find_tlg_by_guid(const PBYTE, PBYTE mz, const char *section_name, PBYTE &out_res);
   int find_tlgs_by_guid(const PBYTE, PBYTE mz, std::list<PBYTE> &);
   // template horror
   template <typename F>
   void traverse_simple_state_graph(PBYTE psp, F func, const char *func_name, int max_edges = 100)
   {
     statefull_graph<PBYTE, int> cgraph;
     std::list<std::pair<PBYTE, int> > addr_list;
     auto curr = std::make_pair(psp, 0);
     addr_list.push_back(curr);
     int edge_gen = 0;
     int edge_n = 0;
     while( edge_gen < max_edges )
     {
       for ( auto iter = addr_list.cbegin(); iter != addr_list.cend(); ++iter )
       {
          psp = iter->first;
          int state = iter->second;
          if ( m_verbose && func_name != NULL )
            printf("%s: %p, state %d, edge_gen %d, edge_n %d\n", func_name, psp, state, edge_gen, edge_n);
          if ( cgraph.in_ranges(psp) )
            continue;
          if ( !setup(psp) )
            continue;
          regs_pad used_regs;
          for ( ; ; )
          {
            if ( !disasm(state) || is_ret() )
              break;
            if ( is_adrp(used_regs) )
              continue;
            if ( check_jmps(cgraph, state) )
              continue;
            PBYTE b_addr = NULL;
            if ( is_b_jimm(b_addr) )
            {
              cgraph.add(b_addr, state);
              break;
            }
            // interface for F: -1 - break, 1 - exit
            int res = func(&state, &used_regs);
            if ( res < 0 )
              break;
            else if ( res )
              return;
          }
          cgraph.add_range(psp, m_psp - psp);
       }
       // prepare for next edge generation
       edge_gen++;
       if ( !cgraph.delete_ranges(&cgraph.ranges, &addr_list) )
         break;
     }
   }
   // internal methods
   int find_etw_guid(const PBYTE, PBYTE mz, PBYTE &out_res);
   int resolve_etw(PBYTE aux_guid, PBYTE mz, PBYTE &out_res);
   int disasm_etw(PBYTE psp, PBYTE aux_addr, PBYTE &out_res);
   int find_tlg_guid4(const PBYTE addr, PBYTE mz, PBYTE &out_res);
   int find_tlgs_guid4(const PBYTE addr, PBYTE mz, std::list<PBYTE> &);
   int find_tlg_ref(PBYTE addr, PBYTE mz, PBYTE &out_res);
   int find_tlg_ref(PBYTE addr, PBYTE mz, const char *section_name, PBYTE &out_res);
   // mcgen data
   int find_Provider_Context(const PBYTE guid, const char *section_name, PBYTE mz, PBYTE &out_res);
   int resolve_Provider_Context(PBYTE what, PBYTE mz, const char *section_name, PBYTE &out_res);
   int disasm_mcgen(PBYTE psp, PBYTE aux_addr, PBYTE &out_res);
   // load config data
   PBYTE m_cookie;
   PBYTE m_GuardCFCheckFunctionPointer;
   PBYTE m_GuardCFDispatchFunctionPointer;
   // pdata
   DWORD m_pdata_rva;
   DWORD m_pdata_size;

   // disasm data
   int m_verbose;
   PBYTE m_psp;
   arm64_pe_file *m_pe;
   // pe file data
   exports_dict *m_ed;
   struct ad_insn m_dis;
};
