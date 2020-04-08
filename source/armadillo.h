#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include "adefs.h"

#ifdef __cplusplus
extern "C" {
#endif

void armadillo_init(struct ad_insn *dis);
int ArmadilloDisassemble(unsigned int opcode, uint64 PC, struct ad_insn *out);

#ifdef __cplusplus
 }
#endif

#endif
