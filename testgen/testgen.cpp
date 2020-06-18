// testgen.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "../source/armadillo.h"
#include "../source/bits.h"

static const char *s_fname = "out.bin";

int main(int argc, char **argv)
{
  const DWORD max = 1 << 29;
  const DWORD op2 = 2 << 25;
  DWORD total = 0;
  DWORD good = 0;
  DWORD false_good = 0;
  DWORD bad = 0;
  struct ad_insn dis;

  if ( 1 == argc )
  {
    FILE *fp = fopen(s_fname, "wb");
    if ( NULL == fp )
    {
      printf("Cannot open %s, error %d\n", s_fname, ::GetLastError());
      return 0;
    }
    for ( DWORD i = 0; i < max; i++ )
    {
      // make new sve opcode
      DWORD val = i & 0x1FFFFFF;
      DWORD head = i >> 25;
      val |= op2;
      val |= head << 28;
      fwrite(&val, sizeof(val), 1, fp);
    }
    fclose(fp);
  } else if ( !strcmp(argv[1], "-t") )
  {
    for ( DWORD i = 0; i < max; i++ )
    {
      // make new sve opcode
      DWORD val = i & 0x1FFFFFF;
      DWORD head = i >> 25;
      val |= op2;
      val |= head << 28;
      total++;
      __try
      {
        if (ArmadilloDisassemble(val, (ULONGLONG)0, &dis))
          bad++;
        else 
        {
          good++;
          if ( dis.instr_id == AD_NONE && dis.group != AD_G_Reserved )
          {
            false_good++;
            printf("%X\n", val);
          }
        }
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        printf("exception %X", GetExceptionCode());
      }
    }
    printf("total %d, good %d, false good %d, bad %d\n", total, good, false_good, bad);
  } else if ( !strcmp(argv[1], "-n") )
  {
    for ( DWORD i = 0; ; i++ )
    {
      unsigned op0 = bits(i, 25, 28);
      if ( op0 == 2 )
        continue;
      total++;
      __try
      {
        if (ArmadilloDisassemble(i, (ULONGLONG)0, &dis))
          bad++;
        else 
        {
          good++;
          if ( dis.instr_id == AD_NONE && dis.group != AD_G_Reserved )
          {
            false_good++;
            printf("%X\n", i);
          }
        }
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        printf("exception %X", GetExceptionCode());
      }
      if ( i == 0xffffffff )
        break;
    }
    printf("total %X, good %X, false good %X, bad %X\n", total, good, false_good, bad);
  }
  return 1;
}

