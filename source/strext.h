#ifndef _STREXT_H_
#define _STREXT_H_

#include <stdarg.h>

int vconcat(char *, const char *, va_list);
int concat(char *, const char *, ...);

#endif
