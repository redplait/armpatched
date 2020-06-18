#include "bits.h"

static const unsigned bit_mask[] = {
 1,    // 0
 3,    // 1
 7,    // 2
 0xf,  // 3
 0x1f, // 4
 0x3f, // 5
 0x7f, // 6
 0xff, // 7
};

unsigned int bits(unsigned int number, unsigned int start, unsigned int end)
{
    unsigned int amount = end - start;
#ifdef _DEBUG
    if ( end < start )
      abort();
#endif /* _DEBUG */
    if ( amount < 8 )
      return (number >> start) & bit_mask[amount];
    else {
      ++amount;
      {
        unsigned int mask = ((1 << amount) - 1) << start;

        return (number & mask) >> start;
      }
   }
}

unsigned int sign_extend(unsigned int number, int numbits){
    if(number & (1 << (numbits - 1)))
        return number | ~((1 << numbits) - 1);

    return number;
}

uint64 sign_ext64(uint64 number, int numbits)
{
    if(number & (1I64 << (numbits - 1)))
        return number | ~((1I64 << numbits) - 1);

    return number;
}