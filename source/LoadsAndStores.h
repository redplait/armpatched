#ifndef _LOADSANDSTORES_H_
#define _LOADSANDSTORES_H_

#define NO_ALLOCATE 0
#define POST_INDEXED 1
#define OFFSET 2
#define PRE_INDEXED 3

#define UNSIGNED_IMMEDIATE -1

#define UNSCALED_IMMEDIATE 0
#define IMMEDIATE_POST_INDEXED 1
#define UNPRIVILEGED 2
#define IMMEDIATE_PRE_INDEXED 3

static const char *const unscaled_instr_tbl[] = {
    "sturb",
    "ldurb",
    "ldursb",
    "ldursb",
    "stur",
    "ldur",
    "stur",
    "ldur",
    "sturh",
    "ldurh",
    "ldursh",
    "ldursh",
    "stur",
    "ldur",
    NULL,
    NULL,
    "stur",
    "ldur",
    "ldursw",
    NULL,
    "stur",
    "ldur",
    NULL,
    NULL,
    "stur",
    "ldur",
    "prfm",
    NULL,
    "stur",
    "ldur" };

static const char *const pre_post_unsigned_register_idx_instr_tbl[] = {
    "strb",
    "ldrb",
    "ldrsb",
    "ldrsb",
    "str",
    "ldr",
    "str",
    "ldr",
    "strh",
    "ldrh",
    "ldrsh",
    "ldrsh",
    "str",
    "ldr",
    NULL,
    NULL,
    "str",
    "ldr",
    "ldrsw",
    NULL,
    "str",
    "ldr",
    NULL,
    NULL,
    "str",
    "ldr",
    NULL,
    NULL,
    "str",
    "ldr" };

static const char *const unprivileged_instr_tbl[] = {
    "sttrb",
    "ldtrb",
    "ldtrsb",
    "ldtrsb",
    NULL,
    NULL,
    NULL,
    NULL,
    "sttrh",
    "ldtrh",
    "ldtrsh",
    "ldtrsh",
    NULL,
    NULL,
    NULL,
    NULL,
    "sttr",
    "ldtr",
    "ldtrsw",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "sttr",
    "ldtr",
    NULL };

int LoadsAndStoresDisassemble(struct instruction *, struct ad_insn *);

#endif
