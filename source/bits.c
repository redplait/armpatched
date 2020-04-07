#include "bits.h"

unsigned int bits(unsigned int number, unsigned int start, unsigned int end){
    unsigned int amount = (end - start) + 1;
    unsigned int mask = ((1 << amount) - 1) << start;

    return (number & mask) >> start;
}

unsigned int sign_extend(unsigned int number, int numbits){
    if(number & (1 << (numbits - 1)))
        return number | ~((1 << numbits) - 1);

    return number;
}
