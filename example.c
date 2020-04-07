#include <stdio.h>
#include <stdlib.h>

#include "source/armadillo.h"
#include "source/strext.h"

const char *decode_cond(unsigned int cond);

static const char *const AD_INSTR_TABLE[] = {
    "AD_INSTR_ADC",
    "AD_INSTR_ADCS",
    "AD_INSTR_ADD",
    "AD_INSTR_ADDG",
    "AD_INSTR_ADDS",
    "AD_INSTR_ADR",
    "AD_INSTR_ADRP",
    "AD_INSTR_AND",
    "AD_INSTR_ANDS",
    "AD_INSTR_ASR",
    "AD_INSTR_ASRV",
    "AD_INSTR_AT",
    "AD_INSTR_AUTDA",
    "AD_INSTR_AUTDZA",
    "AD_INSTR_AUTDB",
    "AD_INSTR_AUTDZB",
    "AD_INSTR_AUTIA",
    "AD_INSTR_AUTIZA",
    "AD_INSTR_AUTIA1716",
    "AD_INSTR_AUTIASP",
    "AD_INSTR_AUTIAZ",
    "AD_INSTR_AUTIB",
    "AD_INSTR_AUTIZB",
    "AD_INSTR_AUTIB1716",
    "AD_INSTR_AUTIBSP",
    "AD_INSTR_AUTIBZ",
    "AD_INSTR_AXFLAG",
    "AD_INSTR_ARM_DDI",
    "AD_INSTR_B",
    "AD_INSTR_BFC",
    "AD_INSTR_BFI",
    "AD_INSTR_BFM",
    "AD_INSTR_BFXIL",
    "AD_INSTR_BIC",
    "AD_INSTR_BICS",
    "AD_INSTR_BL",
    "AD_INSTR_BLR",
    "AD_INSTR_BLRAAZ",
    "AD_INSTR_BLRAA",
    "AD_INSTR_BLRABZ",
    "AD_INSTR_BLRAB",
    "AD_INSTR_BR",
    "AD_INSTR_BRAAZ",
    "AD_INSTR_BRAA",
    "AD_INSTR_BRABZ",
    "AD_INSTR_BRAB",
    "AD_INSTR_BRK",
    "AD_INSTR_BTI",
    "AD_INSTR_CASAB",
    "AD_INSTR_CASALB",
    "AD_INSTR_CASB",
    "AD_INSTR_CASLB",
    "AD_INSTR_CASAH",
    "AD_INSTR_CASALH",
    "AD_INSTR_CASH",
    "AD_INSTR_CASLH",
    "AD_INSTR_CASP",
    "AD_INSTR_CASPA",
    "AD_INSTR_CASPAL",
    "AD_INSTR_CASPL",
    "AD_INSTR_CAS",
    "AD_INSTR_CASA",
    "AD_INSTR_CASAL",
    "AD_INSTR_CASL",
    "AD_INSTR_CBNZ",
    "AD_INSTR_CBZ",
    "AD_INSTR_CCMN",
    "AD_INSTR_CCMP",
    "AD_INSTR_CFINV",
    "AD_INSTR_CFP",
    "AD_INSTR_CINC",
    "AD_INSTR_CINV",
    "AD_INSTR_CLREX",
    "AD_INSTR_CLS",
    "AD_INSTR_CLZ",
    "AD_INSTR_CMN",
    "AD_INSTR_CMP",
    "AD_INSTR_CMPP",
    "AD_INSTR_CNEG",
    "AD_INSTR_CPP",
    "AD_INSTR_CRC32B",
    "AD_INSTR_CRC32H",
    "AD_INSTR_CRC32W",
    "AD_INSTR_CRC32X",
    "AD_INSTR_CRC32CB",
    "AD_INSTR_CRC32CH",
    "AD_INSTR_CRC32CW",
    "AD_INSTR_CRC32CX",
    "AD_INSTR_CSDB",
    "AD_INSTR_CSEL",
    "AD_INSTR_CSET",
    "AD_INSTR_CSETM",
    "AD_INSTR_CSINC",
    "AD_INSTR_CSINV",
    "AD_INSTR_CSNEG",
    "AD_INSTR_DC",
    "AD_INSTR_DCPS1",
    "AD_INSTR_DCPS2",
    "AD_INSTR_DCPS3",
    "AD_INSTR_DMB",
    "AD_INSTR_DRPS",
    "AD_INSTR_DSB",
    "AD_INSTR_DVP",
    "AD_INSTR_EON",
    "AD_INSTR_EOR",
    "AD_INSTR_ERET",
    "AD_INSTR_ERETAA",
    "AD_INSTR_ERETAB",
    "AD_INSTR_ESB",
    "AD_INSTR_EXTR",
    "AD_INSTR_GMI",
    "AD_INSTR_HINT",
    "AD_INSTR_HLT",
    "AD_INSTR_HVC",
    "AD_INSTR_IC",
    "AD_INSTR_IRG",
    "AD_INSTR_ISB",
    "AD_INSTR_LDADDAB",
    "AD_INSTR_LDADDALB",
    "AD_INSTR_LDADDB",
    "AD_INSTR_LDADDLB",
    "AD_INSTR_LDADDAH",
    "AD_INSTR_LDADDALH",
    "AD_INSTR_LDADDH",
    "AD_INSTR_LDADDLH",
    "AD_INSTR_LDADD",
    "AD_INSTR_LDADDA",
    "AD_INSTR_LDADDAL",
    "AD_INSTR_LDADDL",
    "AD_INSTR_LDAPR",
    "AD_INSTR_LDAPRB",
    "AD_INSTR_LDAPRH",
    "AD_INSTR_LDAPUR",
    "AD_INSTR_LDAPURB",
    "AD_INSTR_LDAPURH",
    "AD_INSTR_LDAPURSB",
    "AD_INSTR_LDAPURSH",
    "AD_INSTR_LDAPURSW",
    "AD_INSTR_LDAR",
    "AD_INSTR_LDARB",
    "AD_INSTR_LDARH",
    "AD_INSTR_LDAXP",
    "AD_INSTR_LDAXR",
    "AD_INSTR_LDAXRB",
    "AD_INSTR_LDAXRH",
    "AD_INSTR_LDCLRAB",
    "AD_INSTR_LDCLRALB",
    "AD_INSTR_LDCLRB",
    "AD_INSTR_LDCLRLB",
    "AD_INSTR_LDCLRAH",
    "AD_INSTR_LDCLRALH",
    "AD_INSTR_LDCLRH",
    "AD_INSTR_LDCLRLH",
    "AD_INSTR_LDCLR",
    "AD_INSTR_LDCLRA",
    "AD_INSTR_LDCLRAL",
    "AD_INSTR_LDCLRL",
    "AD_INSTR_LDEORAB",
    "AD_INSTR_LDEORALB",
    "AD_INSTR_LDEORB",
    "AD_INSTR_LDEORLB",
    "AD_INSTR_LDEORAH",
    "AD_INSTR_LDEORALH",
    "AD_INSTR_LDEORH",
    "AD_INSTR_LDEORLH",
    "AD_INSTR_LDEOR",
    "AD_INSTR_LDEORA",
    "AD_INSTR_LDEORAL",
    "AD_INSTR_LDEORL",
    "AD_INSTR_LDG",
    "AD_INSTR_LDGM",
    "AD_INSTR_LDLARB",
    "AD_INSTR_LDLARH",
    "AD_INSTR_LDLAR",
    "AD_INSTR_LDNP",
    "AD_INSTR_LDP",
    "AD_INSTR_LDPSW",
    "AD_INSTR_LDR",
    "AD_INSTR_LDRAA",
    "AD_INSTR_LDRAB",
    "AD_INSTR_LDRB",
    "AD_INSTR_LDRH",
    "AD_INSTR_LDRSB",
    "AD_INSTR_LDRSH",
    "AD_INSTR_LDRSW",
    "AD_INSTR_LDSETAB",
    "AD_INSTR_LDSETALB",
    "AD_INSTR_LDSETB",
    "AD_INSTR_LDSETLB",
    "AD_INSTR_LDSETAH",
    "AD_INSTR_LDSETALH",
    "AD_INSTR_LDSETH",
    "AD_INSTR_LDSETLH",
    "AD_INSTR_LDSET",
    "AD_INSTR_LDSETA",
    "AD_INSTR_LDSETAL",
    "AD_INSTR_LDSETL",
    "AD_INSTR_LDSMAXAB",
    "AD_INSTR_LDSMAXALB",
    "AD_INSTR_LDSMAXB",
    "AD_INSTR_LDSMAXLB",
    "AD_INSTR_LDSMAXAH",
    "AD_INSTR_LDSMAXALH",
    "AD_INSTR_LDSMAXH",
    "AD_INSTR_LDSMAXLH",
    "AD_INSTR_LDSMAX",
    "AD_INSTR_LDSMAXA",
    "AD_INSTR_LDSMAXAL",
    "AD_INSTR_LDSMAXL",
    "AD_INSTR_LDSMINAB",
    "AD_INSTR_LDSMINALB",
    "AD_INSTR_LDSMINB",
    "AD_INSTR_LDSMINLB",
    "AD_INSTR_LDSMINAH",
    "AD_INSTR_LDSMINALH",
    "AD_INSTR_LDSMINH",
    "AD_INSTR_LDSMINLH",
    "AD_INSTR_LDSMIN",
    "AD_INSTR_LDSMINA",
    "AD_INSTR_LDSMINAL",
    "AD_INSTR_LDSMINL",
    "AD_INSTR_LDTR",
    "AD_INSTR_LDTRB",
    "AD_INSTR_LDTRH",
    "AD_INSTR_LDTRSB",
    "AD_INSTR_LDTRSH",
    "AD_INSTR_LDTRSW",
    "AD_INSTR_LDUMAXAB",
    "AD_INSTR_LDUMAXALB",
    "AD_INSTR_LDUMAXB",
    "AD_INSTR_LDUMAXLB",
    "AD_INSTR_LDUMAXAH",
    "AD_INSTR_LDUMAXALH",
    "AD_INSTR_LDUMAXH",
    "AD_INSTR_LDUMAXLH",
    "AD_INSTR_LDUMAX",
    "AD_INSTR_LDUMAXA",
    "AD_INSTR_LDUMAXAL",
    "AD_INSTR_LDUMAXL",
    "AD_INSTR_LDUMINAB",
    "AD_INSTR_LDUMINALB",
    "AD_INSTR_LDUMINB",
    "AD_INSTR_LDUMINLB",
    "AD_INSTR_LDUMINAH",
    "AD_INSTR_LDUMINALH",
    "AD_INSTR_LDUMINH",
    "AD_INSTR_LDUMINLH",
    "AD_INSTR_LDUMIN",
    "AD_INSTR_LDUMINA",
    "AD_INSTR_LDUMINAL",
    "AD_INSTR_LDUMINL",
    "AD_INSTR_LDUR",
    "AD_INSTR_LDURB",
    "AD_INSTR_LDURH",
    "AD_INSTR_LDURSB",
    "AD_INSTR_LDURSH",
    "AD_INSTR_LDURSW",
    "AD_INSTR_LDXP",
    "AD_INSTR_LDXR",
    "AD_INSTR_LDXRB",
    "AD_INSTR_LDXRH",
    "AD_INSTR_LSL",
    "AD_INSTR_LSLV",
    "AD_INSTR_LSR",
    "AD_INSTR_LSRV",
    "AD_INSTR_MADD",
    "AD_INSTR_MNEG",
    "AD_INSTR_MOV",
    "AD_INSTR_MOVK",
    "AD_INSTR_MOVN",
    "AD_INSTR_MOVZ",
    "AD_INSTR_MRS",
    "AD_INSTR_MSR",
    "AD_INSTR_MSUB",
    "AD_INSTR_MUL",
    "AD_INSTR_MVN",
    "AD_INSTR_NEG",
    "AD_INSTR_NEGS",
    "AD_INSTR_NGC",
    "AD_INSTR_NGCS",
    "AD_INSTR_NOP",
    "AD_INSTR_ORN",
    "AD_INSTR_ORR",
    "AD_INSTR_PACDA",
    "AD_INSTR_PACDZA",
    "AD_INSTR_PACDB",
    "AD_INSTR_PACDZB",
    "AD_INSTR_PACGA",
    "AD_INSTR_PACIA",
    "AD_INSTR_PACIZA",
    "AD_INSTR_PACIA1716",
    "AD_INSTR_PACIASP",
    "AD_INSTR_PACIAZ",
    "AD_INSTR_PACIB",
    "AD_INSTR_PACIZB",
    "AD_INSTR_PACIB1716",
    "AD_INSTR_PACIBSP",
    "AD_INSTR_PACIBZ",
    "AD_INSTR_PRFM",
    "AD_INSTR_PRFUM",
    "AD_INSTR_PSB_CSYNC",
    "AD_INSTR_PSSBB",
    "AD_INSTR_RBIT",
    "AD_INSTR_RET",
    "AD_INSTR_RETAA",
    "AD_INSTR_RETAB",
    "AD_INSTR_REV",
    "AD_INSTR_REV16",
    "AD_INSTR_REV32",
    "AD_INSTR_REV64",
    "AD_INSTR_RMIF",
    "AD_INSTR_ROR",
    "AD_INSTR_RORV",
    "AD_INSTR_SB",
    "AD_INSTR_SBC",
    "AD_INSTR_SBCS",
    "AD_INSTR_SBFIZ",
    "AD_INSTR_SBFM",
    "AD_INSTR_SBFX",
    "AD_INSTR_SDIV",
    "AD_INSTR_SETF8",
    "AD_INSTR_SETF16",
    "AD_INSTR_SEV",
    "AD_INSTR_SEVL",
    "AD_INSTR_SMADDL",
    "AD_INSTR_SMC",
    "AD_INSTR_SMNEGL",
    "AD_INSTR_SMSUBL",
    "AD_INSTR_SMULH",
    "AD_INSTR_SMULL",
    "AD_INSTR_SSBB",
    "AD_INSTR_ST2G",
    "AD_INSTR_STADDB",
    "AD_INSTR_STADDLB",
    "AD_INSTR_STADDH",
    "AD_INSTR_STADDLH",
    "AD_INSTR_STADD",
    "AD_INSTR_STADDL",
    "AD_INSTR_STCLRB",
    "AD_INSTR_STCLRLB",
    "AD_INSTR_STCLRH",
    "AD_INSTR_STCLRLH",
    "AD_INSTR_STCLR",
    "AD_INSTR_STCLRL",
    "AD_INSTR_STEORB",
    "AD_INSTR_STEORLB",
    "AD_INSTR_STEORH",
    "AD_INSTR_STEORLH",
    "AD_INSTR_STEOR",
    "AD_INSTR_STEORL",
    "AD_INSTR_STG",
    "AD_INSTR_STGM",
    "AD_INSTR_STGP",
    "AD_INSTR_STLLRB",
    "AD_INSTR_STLLRH",
    "AD_INSTR_STLLR",
    "AD_INSTR_STLR",
    "AD_INSTR_STLRB",
    "AD_INSTR_STLRH",
    "AD_INSTR_STLUR",
    "AD_INSTR_STLURB",
    "AD_INSTR_STLURH",
    "AD_INSTR_STLXP",
    "AD_INSTR_STLXR",
    "AD_INSTR_STLXRB",
    "AD_INSTR_STLXRH",
    "AD_INSTR_STNP",
    "AD_INSTR_STP",
    "AD_INSTR_STR",
    "AD_INSTR_STRB",
    "AD_INSTR_STRH",
    "AD_INSTR_STSETB",
    "AD_INSTR_STSETLB",
    "AD_INSTR_STSETH",
    "AD_INSTR_STSETLH",
    "AD_INSTR_STSET",
    "AD_INSTR_STSETL",
    "AD_INSTR_STSMAXB",
    "AD_INSTR_STSMAXLB",
    "AD_INSTR_STSMAXH",
    "AD_INSTR_STSMAXLH",
    "AD_INSTR_STSMAX",
    "AD_INSTR_STSMAXL",
    "AD_INSTR_STSMINB",
    "AD_INSTR_STSMINLB",
    "AD_INSTR_STSMINH",
    "AD_INSTR_STSMINLH",
    "AD_INSTR_STSMIN",
    "AD_INSTR_STSMINL",
    "AD_INSTR_STTR",
    "AD_INSTR_STTRB",
    "AD_INSTR_STTRH",
    "AD_INSTR_STUMAXB",
    "AD_INSTR_STUMAXLB",
    "AD_INSTR_STUMAXH",
    "AD_INSTR_STUMAXLH",
    "AD_INSTR_STUMAX",
    "AD_INSTR_STUMAXL",
    "AD_INSTR_STUMINB",
    "AD_INSTR_STUMINLB",
    "AD_INSTR_STUMINH",
    "AD_INSTR_STUMINLH",
    "AD_INSTR_STUMIN",
    "AD_INSTR_STUMINL",
    "AD_INSTR_STUR",
    "AD_INSTR_STURB",
    "AD_INSTR_STURH",
    "AD_INSTR_STXP",
    "AD_INSTR_STXR",
    "AD_INSTR_STXRB",
    "AD_INSTR_STXRH",
    "AD_INSTR_STZ2G",
    "AD_INSTR_STZG",
    "AD_INSTR_STZGM",
    "AD_INSTR_SUB",
    "AD_INSTR_SUBG",
    "AD_INSTR_SUBP",
    "AD_INSTR_SUBPS",
    "AD_INSTR_SUBS",
    "AD_INSTR_SVC",
    "AD_INSTR_SWPAB",
    "AD_INSTR_SWPALB",
    "AD_INSTR_SWPB",
    "AD_INSTR_SWPLB",
    "AD_INSTR_SWPAH",
    "AD_INSTR_SWPALH",
    "AD_INSTR_SWPH",
    "AD_INSTR_SWPLH",
    "AD_INSTR_SWP",
    "AD_INSTR_SWPA",
    "AD_INSTR_SWPAL",
    "AD_INSTR_SWPL",
    "AD_INSTR_SXTB",
    "AD_INSTR_SXTH",
    "AD_INSTR_SXTW",
    "AD_INSTR_SYS",
    "AD_INSTR_SYSL",
    "AD_INSTR_TBNZ",
    "AD_INSTR_TBZ",
    "AD_INSTR_TLBI",
    "AD_INSTR_TSB_CSYNC",
    "AD_INSTR_TST",
    "AD_INSTR_UBFIZ",
    "AD_INSTR_UBFM",
    "AD_INSTR_UBFX",
    "AD_INSTR_UDF",
    "AD_INSTR_UDIV",
    "AD_INSTR_UMADDL",
    "AD_INSTR_UMNEGL",
    "AD_INSTR_UMSUBL",
    "AD_INSTR_UMULH",
    "AD_INSTR_UMULL",
    "AD_INSTR_UXTB",
    "AD_INSTR_UXTH",
    "AD_INSTR_WFE",
    "AD_INSTR_WFI",
    "AD_INSTR_XAFLAG",
    "AD_INSTR_XPACD",
    "AD_INSTR_XPACI",
    "AD_INSTR_XPACLRI",
    "AD_INSTR_YIELD",
    "AD_INSTR_ABS",
    "AD_INSTR_ADDHN",
    "AD_INSTR_ADDHN2",
    "AD_INSTR_ADDP",
    "AD_INSTR_ADDV",
    "AD_INSTR_AESD",
    "AD_INSTR_AESE",
    "AD_INSTR_AESIMC",
    "AD_INSTR_AESMC",
    "AD_INSTR_BCAX",
    "AD_INSTR_BIF",
    "AD_INSTR_BIT",
    "AD_INSTR_BSL",
    "AD_INSTR_CMEQ",
    "AD_INSTR_CMGE",
    "AD_INSTR_CMGT",
    "AD_INSTR_CMHI",
    "AD_INSTR_CMHS",
    "AD_INSTR_CMLE",
    "AD_INSTR_CMLT",
    "AD_INSTR_CMTST",
    "AD_INSTR_CNT",
    "AD_INSTR_DUP",
    "AD_INSTR_EOR3",
    "AD_INSTR_EXT",
    "AD_INSTR_FABD",
    "AD_INSTR_FABS",
    "AD_INSTR_FACGE",
    "AD_INSTR_FACGT",
    "AD_INSTR_FADD",
    "AD_INSTR_FADDP",
    "AD_INSTR_FCADD",
    "AD_INSTR_FCCMP",
    "AD_INSTR_FCCMPE",
    "AD_INSTR_FCMEQ",
    "AD_INSTR_FCMGE",
    "AD_INSTR_FCMGT",
    "AD_INSTR_FCMLA",
    "AD_INSTR_FCMLE",
    "AD_INSTR_FCMLT",
    "AD_INSTR_FCMP",
    "AD_INSTR_FCMPE",
    "AD_INSTR_FCSEL",
    "AD_INSTR_FCVT",
    "AD_INSTR_FCVTAS",
    "AD_INSTR_FCVTAU",
    "AD_INSTR_FCVTL",
    "AD_INSTR_FCVTL2",
    "AD_INSTR_FCVTMS",
    "AD_INSTR_FCVTMU",
    "AD_INSTR_FCVTN",
    "AD_INSTR_FCVTN2",
    "AD_INSTR_FCVTNS",
    "AD_INSTR_FCVTNU",
    "AD_INSTR_FCVTPS",
    "AD_INSTR_FCVTPU",
    "AD_INSTR_FCVTXN",
    "AD_INSTR_FCVTXN2",
    "AD_INSTR_FCVTZS",
    "AD_INSTR_FCVTZU",
    "AD_INSTR_FDIV",
    "AD_INSTR_FJCVTZS",
    "AD_INSTR_FMADD",
    "AD_INSTR_FMAX",
    "AD_INSTR_FMAXNM",
    "AD_INSTR_FMAXNMP",
    "AD_INSTR_FMAXNMV",
    "AD_INSTR_FMAXP",
    "AD_INSTR_FMAXV",
    "AD_INSTR_FMIN",
    "AD_INSTR_FMINNM",
    "AD_INSTR_FMINNMP",
    "AD_INSTR_FMINNMV",
    "AD_INSTR_FMINP",
    "AD_INSTR_FMINV",
    "AD_INSTR_FMLA",
    "AD_INSTR_FMLAL",
    "AD_INSTR_FMLAL2",
    "AD_INSTR_FMLS",
    "AD_INSTR_FMLSL",
    "AD_INSTR_FMLSL2",
    "AD_INSTR_FMOV",
    "AD_INSTR_FMSUB",
    "AD_INSTR_FMUL",
    "AD_INSTR_FMULX",
    "AD_INSTR_FNEG",
    "AD_INSTR_FNMADD",
    "AD_INSTR_FNMSUB",
    "AD_INSTR_FNMUL",
    "AD_INSTR_FRECPE",
    "AD_INSTR_FRECPS",
    "AD_INSTR_FRECPX",
    "AD_INSTR_FRINT32X",
    "AD_INSTR_FRINT32Z",
    "AD_INSTR_FRINT64X",
    "AD_INSTR_FRINT64Z",
    "AD_INSTR_FRINTA",
    "AD_INSTR_FRINTI",
    "AD_INSTR_FRINTM",
    "AD_INSTR_FRINTN",
    "AD_INSTR_FRINTP",
    "AD_INSTR_FRINTX",
    "AD_INSTR_FRINTZ",
    "AD_INSTR_FRSQRTE",
    "AD_INSTR_FRSQRTS",
    "AD_INSTR_FSQRT",
    "AD_INSTR_FSUB",
    "AD_INSTR_INS",
    "AD_INSTR_LD1",
    "AD_INSTR_LD1R",
    "AD_INSTR_LD2",
    "AD_INSTR_LD2R",
    "AD_INSTR_LD3",
    "AD_INSTR_LD3R",
    "AD_INSTR_LD4",
    "AD_INSTR_LD4R",
    "AD_INSTR_MLA",
    "AD_INSTR_MLS",
    "AD_INSTR_MOVI",
    "AD_INSTR_MVNI",
    "AD_INSTR_NOT",
    "AD_INSTR_PMUL",
    "AD_INSTR_PMULL",
    "AD_INSTR_PMULL2",
    "AD_INSTR_RADDHN",
    "AD_INSTR_RADDHN2",
    "AD_INSTR_RAX1",
    "AD_INSTR_RSHRN",
    "AD_INSTR_RSHRN2",
    "AD_INSTR_RSUBHN",
    "AD_INSTR_RSUBHN2",
    "AD_INSTR_SABA",
    "AD_INSTR_SABAL",
    "AD_INSTR_SABAL2",
    "AD_INSTR_SABD",
    "AD_INSTR_SABDL",
    "AD_INSTR_SABDL2",
    "AD_INSTR_SADALP",
    "AD_INSTR_SADDL",
    "AD_INSTR_SADDL2",
    "AD_INSTR_SADDLP",
    "AD_INSTR_SADDLV",
    "AD_INSTR_SADDW",
    "AD_INSTR_SADDW2",
    "AD_INSTR_SCVTF",
    "AD_INSTR_SDOT",
    "AD_INSTR_SHA1C",
    "AD_INSTR_SHA1H",
    "AD_INSTR_SHA1M",
    "AD_INSTR_SHA1P",
    "AD_INSTR_SHA1SU0",
    "AD_INSTR_SHA1SU1",
    "AD_INSTR_SHA256H2",
    "AD_INSTR_SHA256H",
    "AD_INSTR_SHA256SU0",
    "AD_INSTR_SHA256SU1",
    "AD_INSTR_SHA512H",
    "AD_INSTR_SHA512H2",
    "AD_INSTR_SHA512SU0",
    "AD_INSTR_SHA512SU1",
    "AD_INSTR_SHADD",
    "AD_INSTR_SHL",
    "AD_INSTR_SHLL",
    "AD_INSTR_SHLL2",
    "AD_INSTR_SHRN",
    "AD_INSTR_SHRN2",
    "AD_INSTR_SHSUB",
    "AD_INSTR_SLI",
    "AD_INSTR_SM3PARTW1",
    "AD_INSTR_SM3PARTW2",
    "AD_INSTR_SM3SS1",
    "AD_INSTR_SM3TT1A",
    "AD_INSTR_SM3TT1B",
    "AD_INSTR_SM3TT2A",
    "AD_INSTR_SM3TT2B",
    "AD_INSTR_SM4E",
    "AD_INSTR_SM4EKEY",
    "AD_INSTR_SMAX",
    "AD_INSTR_SMAXP",
    "AD_INSTR_SMAXV",
    "AD_INSTR_SMIN",
    "AD_INSTR_SMINP",
    "AD_INSTR_SMINV",
    "AD_INSTR_SMLAL",
    "AD_INSTR_SMLAL2",
    "AD_INSTR_SMLSL",
    "AD_INSTR_SMLSL2",
    "AD_INSTR_SMOV",
    "AD_INSTR_SMULL2",
    "AD_INSTR_SQABS",
    "AD_INSTR_SQADD",
    "AD_INSTR_SQDMLAL",
    "AD_INSTR_SQDMLAL2",
    "AD_INSTR_SQDMLSL",
    "AD_INSTR_SQDMLSL2",
    "AD_INSTR_SQDMULH",
    "AD_INSTR_SQDMULL",
    "AD_INSTR_SQDMULL2",
    "AD_INSTR_SQNEG",
    "AD_INSTR_SQRDMLAH",
    "AD_INSTR_SQRDMLSH",
    "AD_INSTR_SQRDMULH",
    "AD_INSTR_SQRSHL",
    "AD_INSTR_SQRSHRN",
    "AD_INSTR_SQRSHRN2",
    "AD_INSTR_SQRSHRUN",
    "AD_INSTR_SQRSHRUN2",
    "AD_INSTR_SQSHL",
    "AD_INSTR_SQSHLU",
    "AD_INSTR_SQSHRN",
    "AD_INSTR_SQSHRN2",
    "AD_INSTR_SQSHRUN",
    "AD_INSTR_SQSHRUN2",
    "AD_INSTR_SQSUB",
    "AD_INSTR_SQXTN",
    "AD_INSTR_SQXTN2",
    "AD_INSTR_SQXTUN",
    "AD_INSTR_SQXTUN2",
    "AD_INSTR_SRHADD",
    "AD_INSTR_SRI",
    "AD_INSTR_SRSHL",
    "AD_INSTR_SRSHR",
    "AD_INSTR_SRSRA",
    "AD_INSTR_SSHL",
    "AD_INSTR_SSHLL",
    "AD_INSTR_SSHLL2",
    "AD_INSTR_SSHR",
    "AD_INSTR_SSRA",
    "AD_INSTR_SSUBL",
    "AD_INSTR_SSUBL2",
    "AD_INSTR_SSUBW",
    "AD_INSTR_SSUBW2",
    "AD_INSTR_ST1",
    "AD_INSTR_ST2",
    "AD_INSTR_ST3",
    "AD_INSTR_ST4",
    "AD_INSTR_SUBHN",
    "AD_INSTR_SUBHN2",
    "AD_INSTR_SUQADD",
    "AD_INSTR_SXTL",
    "AD_INSTR_SXTL2",
    "AD_INSTR_TBL",
    "AD_INSTR_TBX",
    "AD_INSTR_TRN1",
    "AD_INSTR_TRN2",
    "AD_INSTR_UABA",
    "AD_INSTR_UABAL",
    "AD_INSTR_UABAL2",
    "AD_INSTR_UABD",
    "AD_INSTR_UABDL",
    "AD_INSTR_UABDL2",
    "AD_INSTR_UADALP",
    "AD_INSTR_UADDL",
    "AD_INSTR_UADDL2",
    "AD_INSTR_UADDLP",
    "AD_INSTR_UADDLV",
    "AD_INSTR_UADDW",
    "AD_INSTR_UADDW2",
    "AD_INSTR_UCVTF",
    "AD_INSTR_UDOT",
    "AD_INSTR_UHADD",
    "AD_INSTR_UHSUB",
    "AD_INSTR_UMAX",
    "AD_INSTR_UMAXP",
    "AD_INSTR_UMAXV",
    "AD_INSTR_UMIN",
    "AD_INSTR_UMINP",
    "AD_INSTR_UMINV",
    "AD_INSTR_UMLAL",
    "AD_INSTR_UMLAL2",
    "AD_INSTR_UMLSL",
    "AD_INSTR_UMLSL2",
    "AD_INSTR_UMOV",
    "AD_INSTR_UMULL2",
    "AD_INSTR_UQADD",
    "AD_INSTR_UQRSHL",
    "AD_INSTR_UQRSHRN",
    "AD_INSTR_UQRSHRN2",
    "AD_INSTR_UQSHL",
    "AD_INSTR_UQSHRN",
    "AD_INSTR_UQSHRN2",
    "AD_INSTR_UQSUB",
    "AD_INSTR_UQXTN",
    "AD_INSTR_UQXTN2",
    "AD_INSTR_URECPE",
    "AD_INSTR_URHADD",
    "AD_INSTR_URSHL",
    "AD_INSTR_URSHR",
    "AD_INSTR_URSQRTE",
    "AD_INSTR_URSRA",
    "AD_INSTR_USHL",
    "AD_INSTR_USHLL",
    "AD_INSTR_USHLL2",
    "AD_INSTR_USHR",
    "AD_INSTR_USQADD",
    "AD_INSTR_USRA",
    "AD_INSTR_USUBL",
    "AD_INSTR_USUBL2",
    "AD_INSTR_USUBW",
    "AD_INSTR_USUBW2",
    "AD_INSTR_UXTL",
    "AD_INSTR_UXTL2",
    "AD_INSTR_UZP1",
    "AD_INSTR_UZP2",
    "AD_INSTR_XAR",
    "AD_INSTR_XTN",
    "AD_INSTR_XTN2",
    "AD_INSTR_ZIP1",
    "AD_INSTR_ZIP2",
};

static const char *AD_GET_SYSREG_STRING(unsigned int encoding){
    switch(encoding){
        case 0xc081: return "ACTLR_EL1";
        case 0xe081: return "ACTLR_EL2";
        case 0xf081: return "ACTLR_EL3";
        case 0xc288: return "AFSR0_EL1";
        case 0xea88: return "AFSR0_EL12";
        case 0xe288: return "AFSR0_EL2";
        case 0xf288: return "AFSR0_EL3";
        case 0xc289: return "AFSR1_EL1";
        case 0xea89: return "AFSR1_EL12";
        case 0xe289: return "AFSR1_EL2";
        case 0xf289: return "AFSR1_EL3";
        case 0xc807: return "AIDR_EL1";
        case 0xc518: return "AMAIR_EL1";
        case 0xed18: return "AMAIR_EL12";
        case 0xe518: return "AMAIR_EL2";
        case 0xf518: return "AMAIR_EL3";
        case 0xde91: return "AMCFGR_EL0";
        case 0xde92: return "AMCGCR_EL0";
        case 0xde94: return "AMCNTENCLR0_EL0";
        case 0xde98: return "AMCNTENCLR1_EL0";
        case 0xde95: return "AMCNTENSET0_EL0";
        case 0xde99: return "AMCNTENSET1_EL0";
        case 0xde90: return "AMCR_EL0";
        case 0xde93: return "AMUSERENR_EL0";
        case 0xc111: return "APDAKeyHi_EL1";
        case 0xc110: return "APDAKeyLo_EL1";
        case 0xc113: return "APDBKeyHi_EL1";
        case 0xc112: return "APDBKeyLo_EL1";
        case 0xc119: return "APGAKeyHi_EL1";
        case 0xc118: return "APGAKeyLo_EL1";
        case 0xc109: return "APIAKeyHi_EL1";
        case 0xc108: return "APIAKeyLo_EL1";
        case 0xc10b: return "APIBKeyHi_EL1";
        case 0xc10a: return "APIBKeyLo_EL1";
        case 0xc802: return "CCSIDR2_EL1";
        case 0xc800: return "CCSIDR_EL1";
        case 0xc801: return "CLIDR_EL1";
        case 0xdf00: return "CNTFRQ_EL0";
        case 0xe708: return "CNTHCTL_EL2";
        case 0xe729: return "CNTHPS_CTL_EL2";
        case 0xe72a: return "CNTHPS_CVAL_EL2";
        case 0xe728: return "CNTHPS_TVAL_EL2";
        case 0xe711: return "CNTHP_CTL_EL2";
        case 0xe712: return "CNTHP_CVAL_EL2";
        case 0xe710: return "CNTHP_TVAL_EL2";
        case 0xe721: return "CNTHVS_CTL_EL2";
        case 0xe722: return "CNTHVS_CVAL_EL2";
        case 0xe720: return "CNTHVS_TVAL_EL2";
        case 0xe719: return "CNTHV_CTL_EL2";
        case 0xe71a: return "CNTHV_CVAL_EL2";
        case 0xe718: return "CNTHV_TVAL_EL2";
        case 0xc708: return "CNTKCTL_EL1";
        case 0xdf01: return "CNTPCT_EL0";
        case 0xff11: return "CNTPS_CTL_EL1";
        case 0xff12: return "CNTPS_CVAL_EL1";
        case 0xff10: return "CNTPS_TVAL_EL1";
        case 0xdf11: return "CNTP_CTL_EL0";
        case 0xef11: return "CNTP_CTL_EL02";
        case 0xdf12: return "CNTP_CVAL_EL0";
        case 0xef12: return "CNTP_CVAL_EL02";
        case 0xdf10: return "CNTP_TVAL_EL0";
        case 0xef10: return "CNTP_TVAL_EL02";
        case 0xdf02: return "CNTVCT_EL0";
        case 0xe703: return "CNTVOFF_EL2";
        case 0xdf19: return "CNTV_CTL_EL0";
        case 0xef19: return "CNTV_CTL_EL02";
        case 0xdf1a: return "CNTV_CVAL_EL0";
        case 0xef1a: return "CNTV_CVAL_EL02";
        case 0xdf18: return "CNTV_TVAL_EL0";
        case 0xef18: return "CNTV_TVAL_EL02";
        case 0xc681: return "CONTEXTIDR_EL1";
        case 0xee81: return "CONTEXTIDR_EL12";
        case 0xe681: return "CONTEXTIDR_EL2";
        case 0xc082: return "CPACR_EL1";
        case 0xe882: return "CPACR_EL12";
        case 0xe08a: return "CPTR_EL2";
        case 0xf08a: return "CPTR_EL3";
        case 0xd000: return "CSSELR_EL1";
        case 0xd801: return "CTR_EL0";
        case 0xc212: return "CurrentEL";
        case 0xe180: return "DACR32_EL2";
        case 0xda11: return "DAIF";
        case 0x83f6: return "DBGAUTHSTATUS_EL1";
        case 0x83ce: return "DBGCLAIMCLR_EL1";
        case 0x83c6: return "DBGCLAIMSET_EL1";
        case 0x9828: return "DBGDTRRX_EL0"; /* DBGDTRTX_EL0 has same encoding */
        case 0x9820: return "DBGDTR_EL0";
        case 0x80a4: return "DBGPRCR_EL1";
        case 0xa038: return "DBGVCR32_EL2";
        case 0xd807: return "DCZID_EL0";
        case 0xc609: return "DISR_EL1";
        case 0xda15: return "DIT";
        case 0xda29: return "DLR_EL0";
        case 0xda28: return "DSPSR_EL0";
        case 0xc201: return "ELR_EL1";
        case 0xea01: return "ELR_EL12";
        case 0xe201: return "ELR_EL2";
        case 0xf201: return "ELR_EL3";
        case 0xc298: return "ERRIDR_EL1";
        case 0xc299: return "ERRSELR_EL1";
        case 0xc2a3: return "ERXADDR_EL1";
        case 0xc2a1: return "ERXCTLR_EL1";
        case 0xc2a0: return "ERXFR_EL1";
        case 0xc2a8: return "ERXMISC0_EL1";
        case 0xc2a9: return "ERXMISC1_EL1";
        case 0xc2aa: return "ERXMISC2_EL1";
        case 0xc2ab: return "ERXMISC3_EL1";
        case 0xc2a6: return "ERXPFGCDN_EL1";
        case 0xc2a5: return "ERXPFGCTL_EL1";
        case 0xc2a4: return "ERXPFGF_EL1";
        case 0xc2a2: return "ERXSTATUS_EL1";
        case 0xc290: return "ESR_EL1";
        case 0xea90: return "ESR_EL12";
        case 0xe290: return "ESR_EL2";
        case 0xf290: return "ESR_EL3";
        case 0xc300: return "FAR_EL1";
        case 0xeb00: return "FAR_EL12";
        case 0xe300: return "FAR_EL2";
        case 0xf300: return "FAR_EL3";
        case 0xd184: return "FPCR";
        case 0xe298: return "FPEXC32_EL2";
        case 0xd194: return "FPSR";
        case 0xc086: return "GCR_EL1";
        case 0xcc0: return "GMID_EL1";
        case 0xe08f: return "HACR_EL2";
        case 0xe088: return "HCR_EL2";
        case 0xe304: return "HPFAR_EL2";
        case 0xe08b: return "HSTR_EL2";
        case 0xc02c: return "ID_AA64AFR0_EL1";
        case 0xc02d: return "ID_AA64AFR1_EL1";
        case 0xc028: return "ID_AA64DFR0_EL1";
        case 0xc029: return "ID_AA64DFR1_EL1";
        case 0xc030: return "ID_AA64ISAR0_EL1";
        case 0xc031: return "ID_AA64ISAR1_EL1";
        case 0xc038: return "ID_AA64MMFR0_EL1";
        case 0xc039: return "ID_AA64MMFR1_EL1";
        case 0xc03a: return "ID_AA64MMFR2_EL1";
        case 0xc020: return "ID_AA64PFR0_EL1";
        case 0xc021: return "ID_AA64PFR1_EL1";
        case 0xc00b: return "ID_AFR0_EL1";
        case 0xc00a: return "ID_DFR0_EL1";
        case 0xc010: return "ID_ISAR0_EL1";
        case 0xc011: return "ID_ISAR1_EL1";
        case 0xc012: return "ID_ISAR2_EL1";
        case 0xc013: return "ID_ISAR3_EL1";
        case 0xc014: return "ID_ISAR4_EL1";
        case 0xc015: return "ID_ISAR5_EL1";
        case 0xc017: return "ID_ISAR6_EL1";
        case 0xc00c: return "ID_MMFR0_EL1";
        case 0xc00d: return "ID_MMFR1_EL1";
        case 0xc00e: return "ID_MMFR2_EL1";
        case 0xc00f: return "ID_MMFR3_EL1";
        case 0xc016: return "ID_MMFR4_EL1";
        case 0xc008: return "ID_PFR0_EL1";
        case 0xc009: return "ID_PFR1_EL1";
        case 0xc01c: return "ID_PFR2_EL1";
        case 0xe281: return "IFSR32_EL2";
        case 0xc608: return "ISR_EL1";
        case 0xc523: return "LORC_EL1";
        case 0xc521: return "LOREA_EL1";
        case 0xc527: return "LORID_EL1";
        case 0xc522: return "LORN_EL1";
        case 0xc520: return "LORSA_EL1";
        case 0xc510: return "MAIR_EL1";
        case 0xed10: return "MAIR_EL12";
        case 0xe510: return "MAIR_EL2";
        case 0xf510: return "MAIR_EL3";
        case 0x8010: return "MDCCINT_EL1";
        case 0x9808: return "MDCCSR_EL0";
        case 0xe089: return "MDCR_EL2";
        case 0xf099: return "MDCR_EL3";
        case 0x8080: return "MDRAR_EL1";
        case 0x8012: return "MDSCR_EL1";
        case 0xc000: return "MIDR_EL1";
        case 0xc005: return "MPIDR_EL1";
        case 0xc018: return "MVFR0_EL1";
        case 0xc019: return "MVFR1_EL1";
        case 0xc01a: return "MVFR2_EL1";
        case 0xda10: return "NZCV";
        case 0x809c: return "OSDLR_EL1";
        case 0x8002: return "OSDTRRX_EL1";
        case 0x801a: return "OSDTRTX_EL1";
        case 0x8032: return "OSECCR_EL1";
        case 0x8084: return "OSLAR_EL1";
        case 0x808c: return "OSLSR_EL1";
        case 0xc213: return "PAN";
        case 0xc3a0: return "PAR_EL1";
        case 0xc4d7: return "PMBIDR_EL1";
        case 0xc4d0: return "PMBLIMITR_EL1";
        case 0xc4d1: return "PMBPTR_EL1";
        case 0xc4d3: return "PMBSR_EL1";
        case 0xdf7f: return "PMCCFILTR_EL0";
        case 0xdce8: return "PMCCNTR_EL0";
        case 0xdce6: return "PMCEID0_EL0";
        case 0xdce7: return "PMCEID1_EL0";
        case 0xdce2: return "PMCNTENCLR_EL0";
        case 0xdce1: return "PMCNTENSET_EL0";
        case 0xdce0: return "PMCR_EL0";
        case 0xc4f2: return "PMINTENCLR_EL1";
        case 0xc4f1: return "PMINTENSET_EL1";
        case 0xc4f6: return "PMMIR_EL1";
        case 0xdce3: return "PMOVSCLR_EL0";
        case 0xdcf3: return "PMOVSSET_EL0";
        case 0xc4c8: return "PMSCR_EL1";
        case 0xecc8: return "PMSCR_EL12";
        case 0xe4c8: return "PMSCR_EL2";
        case 0xdce5: return "PMSELR_EL0";
        case 0xc4cd: return "PMSEVFR_EL1";
        case 0xc4cc: return "PMSFCR_EL1";
        case 0xc4ca: return "PMSICR_EL1";
        case 0xc4cf: return "PMSIDR_EL1";
        case 0xc4cb: return "PMSIRR_EL1";
        case 0xc4ce: return "PMSLATFR_EL1";
        case 0xdce4: return "PMSWINC_EL0";
        case 0xdcf0: return "PMUSERENR_EL0";
        case 0xdcea: return "PMXEVCNTR_EL0";
        case 0xdce9: return "PMXEVTYPER_EL0";
        case 0xc006: return "REVIDR_EL1";
        case 0xc085: return "RGSR_EL1";
        case 0xc602: return "RMR_EL1";
        case 0xe602: return "RMR_EL2";
        case 0xf602: return "RMR_EL3";
        case 0xd920: return "RNDR";
        case 0xd921: return "RNDRRS";
        case 0xc601: return "RVBAR_EL1";
        case 0xe601: return "RVBAR_EL2";
        case 0xf601: return "RVBAR_EL3";
        case 0xf088: return "SCR_EL3";
        case 0xc080: return "SCTLR_EL1";
        case 0xe880: return "SCTLR_EL12";
        case 0xe080: return "SCTLR_EL2";
        case 0xf080: return "SCTLR_EL3";
        case 0xde87: return "SCXTNUM_EL0";
        case 0xc687: return "SCXTNUM_EL1";
        case 0xee87: return "SCXTNUM_EL12";
        case 0xe687: return "SCXTNUM_EL2";
        case 0xf687: return "SCXTNUM_EL3";
        case 0xe099: return "SDER32_EL2";
        case 0xf089: return "SDER32_EL3";
        case 0xc200: return "SPSR_EL1";
        case 0xea00: return "SPSR_EL12";
        case 0xe200: return "SPSR_EL2";
        case 0xf200: return "SPSR_EL3";
        case 0xe219: return "SPSR_abt";
        case 0xe21b: return "SPSR_fiq";
        case 0xe218: return "SPSR_irq";
        case 0xe21a: return "SPSR_und";
        case 0xc210: return "SPSel";
        case 0xc208: return "SP_EL0";
        case 0xe208: return "SP_EL1";
        case 0xf208: return "SP_EL2";
        case 0xda16: return "SSBS";
        case 0xda17: return "TCO";
        case 0xc102: return "TCR_EL1";
        case 0xe902: return "TCR_EL12";
        case 0xe102: return "TCR_EL2";
        case 0xf102: return "TCR_EL3";
        case 0xc2b1: return "TFSRE0_EL1";
        case 0xc2b0: return "TFSR_EL1";
        case 0xeab0: return "TFSR_EL12";
        case 0xe2b0: return "TFSR_EL2";
        case 0xf2b0: return "TFSR_EL3";
        case 0xde83: return "TPIDRRO_EL0";
        case 0xde82: return "TPIDR_EL0";
        case 0xc684: return "TPIDR_EL1";
        case 0xe682: return "TPIDR_EL2";
        case 0xf682: return "TPIDR_EL3";
        case 0xc091: return "TRFCR_EL1";
        case 0xe891: return "TRFCR_EL12";
        case 0xe091: return "TRFCR_EL2";
        case 0xc100: return "TTBR0_EL1";
        case 0xe900: return "TTBR0_EL12";
        case 0xe100: return "TTBR0_EL2";
        case 0xf100: return "TTBR0_EL3";
        case 0xc101: return "TTBR1_EL1";
        case 0xe901: return "TTBR1_EL12";
        case 0xe101: return "TTBR1_EL2";
        case 0xc214: return "UAO";
        case 0xc600: return "VBAR_EL1";
        case 0xee00: return "VBAR_EL12";
        case 0xe600: return "VBAR_EL2";
        case 0xf600: return "VBAR_EL3";
        case 0xe609: return "VDISR_EL2";
        case 0xe005: return "VMPIDR_EL2";
        case 0xe110: return "VNCR_EL2";
        case 0xe000: return "VPIDR_EL2";
        case 0xe293: return "VSESR_EL2";
        case 0xe132: return "VSTCR_EL2";
        case 0xe130: return "VSTTBR_EL2";
        case 0xe10a: return "VTCR_EL2";
        case 0xe108: return "VTTBR_EL2";
        case 0xdea0: return "AMEVCNTR00_EL0";
        case 0xdea1: return "AMEVCNTR01_EL0";
        case 0xdea2: return "AMEVCNTR02_EL0";
        case 0xdea3: return "AMEVCNTR03_EL0";
        case 0xdea4: return "AMEVCNTR04_EL0";
        case 0xdea5: return "AMEVCNTR05_EL0";
        case 0xdea6: return "AMEVCNTR06_EL0";
        case 0xdea7: return "AMEVCNTR07_EL0";
        case 0xdea8: return "AMEVCNTR08_EL0";
        case 0xdea9: return "AMEVCNTR09_EL0";
        case 0xdeaa: return "AMEVCNTR010_EL0";
        case 0xdeab: return "AMEVCNTR011_EL0";
        case 0xdeac: return "AMEVCNTR012_EL0";
        case 0xdead: return "AMEVCNTR013_EL0";
        case 0xdeae: return "AMEVCNTR014_EL0";
        case 0xdeaf: return "AMEVCNTR015_EL0";
        case 0xdee0: return "AMEVCNTR10_EL0";
        case 0xdee1: return "AMEVCNTR11_EL0";
        case 0xdee2: return "AMEVCNTR12_EL0";
        case 0xdee3: return "AMEVCNTR13_EL0";
        case 0xdee4: return "AMEVCNTR14_EL0";
        case 0xdee5: return "AMEVCNTR15_EL0";
        case 0xdee6: return "AMEVCNTR16_EL0";
        case 0xdee7: return "AMEVCNTR17_EL0";
        case 0xdee8: return "AMEVCNTR18_EL0";
        case 0xdee9: return "AMEVCNTR19_EL0";
        case 0xdeea: return "AMEVCNTR110_EL0";
        case 0xdeeb: return "AMEVCNTR111_EL0";
        case 0xdeec: return "AMEVCNTR112_EL0";
        case 0xdeed: return "AMEVCNTR113_EL0";
        case 0xdeee: return "AMEVCNTR114_EL0";
        case 0xdeef: return "AMEVCNTR115_EL0";
        case 0xdeb0: return "AMEVTYPER00_EL0";
        case 0xdeb1: return "AMEVTYPER01_EL0";
        case 0xdeb2: return "AMEVTYPER02_EL0";
        case 0xdeb3: return "AMEVTYPER03_EL0";
        case 0xdeb4: return "AMEVTYPER04_EL0";
        case 0xdeb5: return "AMEVTYPER05_EL0";
        case 0xdeb6: return "AMEVTYPER06_EL0";
        case 0xdeb7: return "AMEVTYPER07_EL0";
        case 0xdeb8: return "AMEVTYPER08_EL0";
        case 0xdeb9: return "AMEVTYPER09_EL0";
        case 0xdeba: return "AMEVTYPER010_EL0";
        case 0xdebb: return "AMEVTYPER011_EL0";
        case 0xdebc: return "AMEVTYPER012_EL0";
        case 0xdebd: return "AMEVTYPER013_EL0";
        case 0xdebe: return "AMEVTYPER014_EL0";
        case 0xdebf: return "AMEVTYPER015_EL0";
        case 0xdef0: return "AMEVTYPER10_EL0";
        case 0xdef1: return "AMEVTYPER11_EL0";
        case 0xdef2: return "AMEVTYPER12_EL0";
        case 0xdef3: return "AMEVTYPER13_EL0";
        case 0xdef4: return "AMEVTYPER14_EL0";
        case 0xdef5: return "AMEVTYPER15_EL0";
        case 0xdef6: return "AMEVTYPER16_EL0";
        case 0xdef7: return "AMEVTYPER17_EL0";
        case 0xdef8: return "AMEVTYPER18_EL0";
        case 0xdef9: return "AMEVTYPER19_EL0";
        case 0xdefa: return "AMEVTYPER110_EL0";
        case 0xdefb: return "AMEVTYPER111_EL0";
        case 0xdefc: return "AMEVTYPER112_EL0";
        case 0xdefd: return "AMEVTYPER113_EL0";
        case 0xdefe: return "AMEVTYPER114_EL0";
        case 0xdeff: return "AMEVTYPER115_EL0";
        case 0x8005: return "DBGBCR0_EL1";
        case 0x800d: return "DBGBCR1_EL1";
        case 0x8015: return "DBGBCR2_EL1";
        case 0x801d: return "DBGBCR3_EL1";
        case 0x8025: return "DBGBCR4_EL1";
        case 0x802d: return "DBGBCR5_EL1";
        case 0x8035: return "DBGBCR6_EL1";
        case 0x803d: return "DBGBCR7_EL1";
        case 0x8045: return "DBGBCR8_EL1";
        case 0x804d: return "DBGBCR9_EL1";
        case 0x8055: return "DBGBCR10_EL1";
        case 0x805d: return "DBGBCR11_EL1";
        case 0x8065: return "DBGBCR12_EL1";
        case 0x806d: return "DBGBCR13_EL1";
        case 0x8075: return "DBGBCR14_EL1";
        case 0x807d: return "DBGBCR15_EL1";
        case 0x8004: return "DBGBVR0_EL1";
        case 0x800c: return "DBGBVR1_EL1";
        case 0x8014: return "DBGBVR2_EL1";
        case 0x801c: return "DBGBVR3_EL1";
        case 0x8024: return "DBGBVR4_EL1";
        case 0x802c: return "DBGBVR5_EL1";
        case 0x8034: return "DBGBVR6_EL1";
        case 0x803c: return "DBGBVR7_EL1";
        case 0x8044: return "DBGBVR8_EL1";
        case 0x804c: return "DBGBVR9_EL1";
        case 0x8054: return "DBGBVR10_EL1";
        case 0x805c: return "DBGBVR11_EL1";
        case 0x8064: return "DBGBVR12_EL1";
        case 0x806c: return "DBGBVR13_EL1";
        case 0x8074: return "DBGBVR14_EL1";
        case 0x807c: return "DBGBVR15_EL1";
        case 0x8007: return "DBGWCR0_EL1";
        case 0x800f: return "DBGWCR1_EL1";
        case 0x8017: return "DBGWCR2_EL1";
        case 0x801f: return "DBGWCR3_EL1";
        case 0x8027: return "DBGWCR4_EL1";
        case 0x802f: return "DBGWCR5_EL1";
        case 0x8037: return "DBGWCR6_EL1";
        case 0x803f: return "DBGWCR7_EL1";
        case 0x8047: return "DBGWCR8_EL1";
        case 0x804f: return "DBGWCR9_EL1";
        case 0x8057: return "DBGWCR10_EL1";
        case 0x805f: return "DBGWCR11_EL1";
        case 0x8067: return "DBGWCR12_EL1";
        case 0x806f: return "DBGWCR13_EL1";
        case 0x8077: return "DBGWCR14_EL1";
        case 0x807f: return "DBGWCR15_EL1";
        case 0x8006: return "DBGWVR0_EL1";
        case 0x800e: return "DBGWVR1_EL1";
        case 0x8016: return "DBGWVR2_EL1";
        case 0x801e: return "DBGWVR3_EL1";
        case 0x8026: return "DBGWVR4_EL1";
        case 0x802e: return "DBGWVR5_EL1";
        case 0x8036: return "DBGWVR6_EL1";
        case 0x803e: return "DBGWVR7_EL1";
        case 0x8046: return "DBGWVR8_EL1";
        case 0x804e: return "DBGWVR9_EL1";
        case 0x8056: return "DBGWVR10_EL1";
        case 0x805e: return "DBGWVR11_EL1";
        case 0x8066: return "DBGWVR12_EL1";
        case 0x806e: return "DBGWVR13_EL1";
        case 0x8076: return "DBGWVR14_EL1";
        case 0x807e: return "DBGWVR15_EL1";
        case 0xdf40: return "PMEVCNTR0_EL0";
        case 0xdf41: return "PMEVCNTR1_EL0";
        case 0xdf42: return "PMEVCNTR2_EL0";
        case 0xdf43: return "PMEVCNTR3_EL0";
        case 0xdf44: return "PMEVCNTR4_EL0";
        case 0xdf45: return "PMEVCNTR5_EL0";
        case 0xdf46: return "PMEVCNTR6_EL0";
        case 0xdf47: return "PMEVCNTR7_EL0";
        case 0xdf48: return "PMEVCNTR8_EL0";
        case 0xdf49: return "PMEVCNTR9_EL0";
        case 0xdf4a: return "PMEVCNTR10_EL0";
        case 0xdf4b: return "PMEVCNTR11_EL0";
        case 0xdf4c: return "PMEVCNTR12_EL0";
        case 0xdf4d: return "PMEVCNTR13_EL0";
        case 0xdf4e: return "PMEVCNTR14_EL0";
        case 0xdf4f: return "PMEVCNTR15_EL0";
        case 0xdf50: return "PMEVCNTR16_EL0";
        case 0xdf51: return "PMEVCNTR17_EL0";
        case 0xdf52: return "PMEVCNTR18_EL0";
        case 0xdf53: return "PMEVCNTR19_EL0";
        case 0xdf54: return "PMEVCNTR20_EL0";
        case 0xdf55: return "PMEVCNTR21_EL0";
        case 0xdf56: return "PMEVCNTR22_EL0";
        case 0xdf57: return "PMEVCNTR23_EL0";
        case 0xdf58: return "PMEVCNTR24_EL0";
        case 0xdf59: return "PMEVCNTR25_EL0";
        case 0xdf5a: return "PMEVCNTR26_EL0";
        case 0xdf5b: return "PMEVCNTR27_EL0";
        case 0xdf5c: return "PMEVCNTR28_EL0";
        case 0xdf5d: return "PMEVCNTR29_EL0";
        case 0xdf5e: return "PMEVCNTR30_EL0";
        case 0xdf5f: return "PMEVCNTR31_EL0";
        case 0xdf60: return "PMEVTYPER0_EL0";
        case 0xdf61: return "PMEVTYPER1_EL0";
        case 0xdf62: return "PMEVTYPER2_EL0";
        case 0xdf63: return "PMEVTYPER3_EL0";
        case 0xdf64: return "PMEVTYPER4_EL0";
        case 0xdf65: return "PMEVTYPER5_EL0";
        case 0xdf66: return "PMEVTYPER6_EL0";
        case 0xdf67: return "PMEVTYPER7_EL0";
        case 0xdf68: return "PMEVTYPER8_EL0";
        case 0xdf69: return "PMEVTYPER9_EL0";
        case 0xdf6a: return "PMEVTYPER10_EL0";
        case 0xdf6b: return "PMEVTYPER11_EL0";
        case 0xdf6c: return "PMEVTYPER12_EL0";
        case 0xdf6d: return "PMEVTYPER13_EL0";
        case 0xdf6e: return "PMEVTYPER14_EL0";
        case 0xdf6f: return "PMEVTYPER15_EL0";
        case 0xdf70: return "PMEVTYPER16_EL0";
        case 0xdf71: return "PMEVTYPER17_EL0";
        case 0xdf72: return "PMEVTYPER18_EL0";
        case 0xdf73: return "PMEVTYPER19_EL0";
        case 0xdf74: return "PMEVTYPER20_EL0";
        case 0xdf75: return "PMEVTYPER21_EL0";
        case 0xdf76: return "PMEVTYPER22_EL0";
        case 0xdf77: return "PMEVTYPER23_EL0";
        case 0xdf78: return "PMEVTYPER24_EL0";
        case 0xdf79: return "PMEVTYPER25_EL0";
        case 0xdf7a: return "PMEVTYPER26_EL0";
        case 0xdf7b: return "PMEVTYPER27_EL0";
        case 0xdf7c: return "PMEVTYPER28_EL0";
        case 0xdf7d: return "PMEVTYPER29_EL0";
        case 0xdf7e: return "PMEVTYPER30_EL0";
        default: return "Implemation Defined System Register"; // XXX S3_<op1>_<Cn>_<Cm>_<op2>
    };
};

static const char *const AD_TYPE_TABLE[] = {
    "AD_OP_REG", "AD_OP_IMM", "AD_OP_SHIFT"
};

static const char *const AD_SHIFT_TABLE[] = {
    "AD_SHIFT_LSL", "AD_SHIFT_LSR", "AD_SHIFT_ASR", "AD_SHIFT_ROR", "AD_SHIFT_MSL"
};

static const char *const AD_IMM_TYPE_TABLE[] = {
    "AD_IMM_INT", "AD_IMM_UINT", "AD_IMM_LONG", "AD_IMM_ULONG", "AD_IMM_FLOAT"
};

static const char *const AD_GROUP_TABLE[] = {
    "AD_G_Reserved", "AD_G_DataProcessingImmediate", "AD_G_BranchExcSys", "AD_G_LoadsAndStores",
    "AD_G_DataProcessingRegister", "AD_G_DataProcessingFloatingPoint"
};

static const char *const AD_COND_TABLE[] = {
    "AD_CC_EQ", "AD_CC_NE", "AD_CC_CS", "AD_CC_CC", "AD_CC_MI", "AD_CC_PL",
    "AD_CC_VS", "AD_CC_VC", "AD_CC_HI", "AD_CC_LS", "AD_CC_GE", "AD_CC_LT",
    "AD_CC_GT", "AD_CC_LE", "AD_CC_AL"
};

static const char *GET_GEN_REG(const char *const *rtbl, unsigned int idx,
        int prefer_zr){
    if(idx > 31)
        return "reg idx oob";

    if(idx == 31 && prefer_zr)
        idx++;

    return rtbl[idx];
}

static const char *GET_FP_REG(const char *const *rtbl, unsigned int idx){
    if(idx > 30)
        return "reg idx oob";

    return rtbl[idx];
}

static void disp_operand(struct ad_operand operand){
    printf("\t\tThis operand is of type %s\n", AD_TYPE_TABLE[operand.type]);

    if(operand.type == AD_OP_REG){
        if(operand.op_reg.sysreg != AD_NONE){
            printf("\t\t\tSystem register: %s\n",
                    AD_GET_SYSREG_STRING(operand.op_reg.sysreg));
        }
        else{
            printf("\t\t\tRegister: ");

            if(operand.op_reg.fp)
                printf("%s\n", GET_FP_REG(operand.op_reg.rtbl, operand.op_reg.rn));
            else{
                const char *reg = GET_GEN_REG(operand.op_reg.rtbl, operand.op_reg.rn, operand.op_reg.zr);
                printf("%s\n", reg);
            }
        }
    }
    else if(operand.type == AD_OP_SHIFT){
        printf("\t\t\tShift type: %s\n\t\t\tAmount: %d\n",
                AD_SHIFT_TABLE[operand.op_shift.type], operand.op_shift.amt);
    }
    else if(operand.type == AD_OP_IMM){
        printf("\t\t\tImmediate type: %s\n\t\t\tValue: ", AD_IMM_TYPE_TABLE[operand.op_imm.type]);

        if(operand.op_imm.type == AD_IMM_INT){
            int v = (int)operand.op_imm.bits;
            printf("%s%#x\n", v < 0 ? "-" : "", v < 0 ? -v : v);
        }
        else if(operand.op_imm.type == AD_IMM_UINT)
            printf("%#x\n", (unsigned int)operand.op_imm.bits);
        else if(operand.op_imm.type == AD_IMM_LONG){
            long v = (long)operand.op_imm.bits;
            printf("%s%#lx\n", v < 0 ? "-" : "", v < 0 ? -v : v);
        }
        else if(operand.op_imm.type == AD_IMM_ULONG)
#ifdef _MSC_VER
            printf("%#I64x\n", operand.op_imm.bits);
#else
            printf("%#lx\n", (unsigned long)operand.op_imm.bits);
#endif /* _MSC_VER */
        else if(operand.op_imm.type == AD_IMM_FLOAT)
            printf("%f\n", *(float *)&operand.op_imm.bits);
        else{
            printf("Unknown immediate type and didn't crash?\n");
            abort();
        }
    }
    else{
        printf("\t\t\tUnknown type and didn't crash?\n");
        abort();
    }
}

static void disp_insn(struct ad_insn *insn){
    printf("Disassembled: %s\n", insn->decoded);

    if(insn->group == AD_NONE)
        return;

    printf("\tThis instruction is %s and is part of group %s\n",
            AD_INSTR_TABLE[insn->instr_id], AD_GROUP_TABLE[insn->group]);
    printf("\tThis instruction has %d decode fields (from left to right):\n", insn->num_fields);

    printf("\t\t");
    for(int i=0; i<insn->num_fields-1; i++)
        printf("%#x, ", insn->fields[i]);

    printf("%#x\n", insn->fields[insn->num_fields - 1]);

    printf("\tThis instruction has %d operands (from left to right):\n", insn->num_operands);

    for(int i=0; i<insn->num_operands; i++)
        disp_operand(insn->operands[i]);

    if(insn->cc != AD_NONE){
        const char *cc = decode_cond(insn->cc);
        printf("\tCode condition: %s\n", cc);
    }
}

int main(int argc, char **argv, const char **envp)
{
    struct ad_insn insn;

#define DISASSEMBLE(opcode, pc) \
    do { \
        if(ArmadilloDisassemble(opcode, pc, &insn)){ \
            printf("Disassembly failed\n"); \
            return 1; \
        } \
        \
        disp_insn(&insn); \
        puts(""); \
    } while(0) \

    if ( argc > 1 )
    {
      for ( int i = 1; i < argc; i++ )
      {
        char *end;
        uint64 pc = 0;
        unsigned int val = strtoul(argv[i], &end, 0x10);
        if (val == 0xC80500F0) pc = 0x1402A5488;
        DISASSEMBLE(_byteswap_ulong(val), pc);
      }
    } else {

    /* sub x5, x4, #0x20 */
    DISASSEMBLE(0xd1008085, 0);
    /* b 0x100007f70 */
    DISASSEMBLE(0x14000010, 0x100007f30);
    /* mrs x0, TTBR0_EL1 */
    DISASSEMBLE(0xd5382000, 0);
    /* ushll2 v6.4s, v2.8h, #1 */
    DISASSEMBLE(0x6f11a446, 0);
    /* bti jc */
    DISASSEMBLE(0xd50324df, 0);
    /* fmov d9, #-0.296875 */
    DISASSEMBLE(0x1e7a7009, 0);
    }
    return 0;
}
