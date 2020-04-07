#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

/* Thanks https://github.com/xerub/macho/blob/master/patchfinder64.c */
static unsigned long RORZeroExtendOnes(unsigned int M, unsigned int N,
        unsigned int R){
    unsigned long val = Ones(M, N);

    if(R == 0)
        return val;

    return ((val >> R) & (((unsigned long)1 << (N - R)) - 1)) |
        ((val & (((unsigned long)1 << R) - 1)) << (N - R));
}

int HighestSetBit(unsigned int number, unsigned int n){
    int ret = -1;
    int i;
    for(i = n-1; i>=0; i--){
        if(number & (1 << i))
            return i;
    }

    return ret;
}

int LowestSetBit(unsigned int number, unsigned int n){
    int ret = n;
    unsigned int i;
    for(i=0; i<n; i++){
        if(number & (1 << i))
            return i;
    }

    return ret;
}

int BitCount(unsigned X, unsigned N){
    int result = 0;
    unsigned int i;
    for(i=0; i<N; i++){
        if(((X >> i) & 1) == 1)
            result++;
    }

    return result;
}

unsigned long Ones(int len, int N){
//    (void)N;
    unsigned long ret = 0;
    int i;
    for(i=len-1; i>=0; i--)
        ret |= ((unsigned long)1 << i);

    return ret;
}

int DecodeBitMasks(unsigned int N, unsigned int imms, unsigned int immr,
        int immediate, unsigned long *out){
    unsigned int num = (N << 6) | (~imms & 0x3f);
    unsigned int len = HighestSetBit(num, 7);
    unsigned int levels;
    unsigned int S, R, esize;
    if(len < 1)
        return -1;

    levels = Ones(len, 0);

    if(immediate && ((imms & levels) == levels))
        return -1;

    S = imms & levels;
    R = immr & levels;
    esize = 1 << len;

    *out = replicate(RORZeroExtendOnes(S + 1, esize, R), sizeof(unsigned long) * CHAR_BIT, esize);

    return 0;
}

/*
 * num: the number to replicate
 * nbits: how many bits make up this number
 * cnt: how many times to replicate
 */
unsigned long replicate(unsigned long num, int nbits, int cnt){
    unsigned long result = 0;
    int i;
    for(i=0; i<cnt; i++){
        result <<= nbits;
        result |= num;
    }

    return result;
}

int MoveWidePreferred(unsigned int sf, unsigned int immN, unsigned int immr,
        unsigned int imms){
    int width = sf == 1 ? 64 : 32;
    unsigned int combined = (immN << 6) | imms;

    if(sf == 1 && (combined >> 6) != 1)
        return 0;

    if(sf == 0 && (combined >> 5) != 0)
        return 0;

    if(imms < 16)
        return (-(int)immr % 16) <= (int)(15 - imms);

    if((int)imms >= (width - 15))
        return (immr % 16) <= (imms - (width - 15));

    return 0;
}

int IsZero(unsigned long x){
    return x == 0;
}

int IsOnes(unsigned long x, int n){
    return x == Ones(n, 0);
}

int BFXPreferred(unsigned int sf, unsigned int uns,
        unsigned int imms, unsigned int immr){
    if(imms < immr)
        return 0;

    if(imms == ((sf << 6) | 0x3f))
        return 0;

    if(immr == 0){
        if(sf == 0 && (imms == 0x7 || imms == 0xf))
            return 0;
        else if(((sf << 1) | uns) == 0x2 && (imms == 0x7 || imms == 0xf || imms == 0x1f))
            return 0;
    }

    return 1;
}

char *decode_reg_extend(unsigned int op){
    switch(op){
        case 0x0:
            return "uxtb";
        case 0x1:
            return "uxth";
        case 0x2:
            return "uxtw";
        case 0x3:
            return "uxtx";
        case 0x4:
            return "sxtb";
        case 0x5:
            return "sxth";
        case 0x6:
            return "sxtw";
        case 0x7:
            return "sxtx";
        default:
            return NULL;
    };
}

const char *decode_cond(unsigned int cond){
    switch(cond){
        case 0: return "eq";
        case 1: return "ne";
        case 2: return "cs";
        case 3: return "cc";
        case 4: return "mi";
        case 5: return "pl";
        case 6: return "vs";
        case 7: return "vc";
        case 8: return "hi";
        case 9: return "ls";
        case 10: return "ge";
        case 11: return "lt";
        case 12: return "gt";
        case 13: return "le";
        case 14: return "al";
        case 15: return "nv";
        default: return NULL;
    };
}

const char *get_arrangement(unsigned int size, unsigned int Q){
    if(size == 0)
        return Q == 0 ? "8b" : "16b";
    if(size == 1)
        return Q == 0 ? "4h" : "8h";
    if(size == 2)
        return Q == 0 ? "2s" : "4s";
    if(size == 3)
        return Q == 0 ? "1d" : "2d";

    return NULL;
}
