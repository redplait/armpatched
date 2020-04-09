#ifndef _BITS_H_
#define _BITS_H_

#ifdef _MSC_VER
# define uint64	unsigned __int64
#else
# define uint64 unsigned long
#endif

unsigned int bits(unsigned int, unsigned int start, unsigned int end);
unsigned int sign_extend(unsigned int number, int numbits);
uint64 sign_ext64(uint64 number, int numbits);

#endif
