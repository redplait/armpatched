#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _concat_internal(char *dst, const char *src, va_list args)
{
   size_t srclen;
   size_t dstlen = 0;
   int w;
   if(!src || !dst)
        return 0;

    srclen = strlen(src);
    if (dst[0])
      dstlen = strlen(dst);
    w = vsprintf_s(dst + dstlen, 79 - dstlen, src, args);
    return w;
}

int concat(char *dst, const char *src, ...){
    int w;
    va_list args;
    va_start(args, src);

    w = _concat_internal(dst, src, args);

    va_end(args);

    return w;
}

int vconcat(char *dst, const char *src, va_list args){
    return _concat_internal(dst, src, args);
}
