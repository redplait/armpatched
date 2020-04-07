#ifndef _UTILS_H_
#define _UTILS_H_

int HighestSetBit(unsigned int, unsigned int);
int LowestSetBit(unsigned int number, unsigned int n);
int BitCount(unsigned, unsigned);
unsigned long Ones(int len, int N);
int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr, int immediate, unsigned long *out);
unsigned long replicate(unsigned long, int, int);
int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr, unsigned int imms);
int IsZero(unsigned long x);
int IsOnes(unsigned long x, int n);
int BFXPreferred(unsigned int sf, unsigned int uns, unsigned int imms, unsigned int immr);
char *decode_reg_extend(unsigned int op);
const char *decode_cond(unsigned int cond);
const char *get_arrangement(unsigned int size, unsigned int Q);

#endif
