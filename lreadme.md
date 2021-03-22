afsm apply FSM rules to one or more files

## Options
-v - set verbose mode

-a - filename with FSM rules. You can apply only one file with FSM rules

-y - filename with YARA rules. You can scan only one file with YARA rules

### FSM Syntax
Each rule must start with *section* keyword - it sets section for states like load/store etc. If you want track loading from other section you should use states with *s* prefix like sload/sstore

Then you peek function to apply this rule. This can be done in several ways:

### func
*func* name of exported function

### yfunc
*yfunc* name of YARA rule. If file with YARA rules is given then YARA first scan all input files. This makes it possible to find function by signatures

### sfunc
*sfunc* index in global storage. This is how you can apply FSM rules to any previously found functions

### fsection
Finally if you can't identify your function afsm can try to find it for you. Search order is

* find constant in constants pool and then find function using this constant. This search happens if you have one or more *const* state
* find constant from .rdata section nd then find function using this constant. This search happens if you have one or more *rdata*/*guid* state
* find functions loading some symbol from IAT. This search happens if you have one or more *limp* state
* find functions calling some imported function. This search happens if you have one or more *call_imp* state

FSM rules are applied to each candidate found only once. for example if some function was selected while searching constants in .rdata and the use of rule did not lead to success it will be skipped in remaining searchings

And then you can have list of states

## States
Each scanned file has it's own global storage - just some hashmap where key is nonzero integer and key is some found offset. You can have prefix *stg* index in state

Second possible prefix is *wait*. It instructs FSM to skip all before this rule will match (or all codeblocks will end)

### load
if no argument is given then track loading of 64bit value from *section*, else track loading of exported symbol

### ldrb
if no argument is given then track loading of 8bit value from *section*, else track loading of exported symbol

### ldrh
if no argument is given then track loading of 16bit value from *section*, else track loading of exported symbol

### sload
argument - name of section from which load of 64bit value is expected 

### sldrb
argument - name of section from which load of 8bit value is expected 

### sldrh
argument - name of section from which load of 16bit value is expected 

### store
if no argument is given then track storing of 64bit value to *section*, else track storing of exported symbol

### strb
if no argument is given then track storing of 8bit value to *section*, else track storing of exported symbol

### strh
if no argument is given then track storing of 16bit value to *section*, else track storing of exported symbol

### sstore
argument - name of section in which store of 64bit value is expected 

### sstrb
argument - name of section in which store of 8bit value is expected 

### sstrh
argument - name of section in which store of 16bit value is expected 

### gload/gldrb/gldrh
argument - index in global storage, rule will expect loading of some already known address

### gstore/gstrb/gstrh
argument - index in global storage, rule will expect storing in some already known address

### const
load some integer constant from constant pool
 
### ldr_cookie
expect loading of IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie

### call_icall
expect calling of IMAGE_LOAD_CONFIG_DIRECTORY.GuardCFCheckFunctionPointer function

### rdata
load some 8 byte constant from .rdata section
 
### guid
load 16 byte GUID from .rdata section. Actually rdata and guid could be one state with variable size
 
### limp
argument - name of imported symbol. expect loading of some imported symbol

### call_imp
argument - name of imported function. expect calling of some imported function

### call_dimp
argument - name of function from delayed IAT

### call_exp
argument - name of exported function

### call
just call of some function. probably you just want to store address of function in global storage

### gcall
argument - index in global storage, rule will expect call with this already known address

### ldrx
ldr regXX, reg, imm. argument - index of register in ldr instruction

### strx
str regXX, reg, imm. argument - index of register in str instruction

### addx
add regXX, reg, imm. argument - index of register in add instruction

### movx
mov regXX, imm. argument - index of register in mov instruction

