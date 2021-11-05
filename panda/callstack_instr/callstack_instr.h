#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "prog_point.h"

// TODO: add the typedef macro so it generates the function + typedef

//PPP_CB_TYPEDEF(void, on_call, CPUState *env, target_ulong func);
//PPP_CB_TYPEDEF(void, on_ret, CPUState *env, target_ulong func);
void on_call(CPUState *env, target_ulong func);
typedef void (*on_call_t)(CPUState *env, target_ulong func);
void on_ret(CPUState *env, target_ulong func);
typedef void (*on_ret_t)(CPUState *env, target_ulong func);

// Public interface

// Get up to n callers from the given stack in use at this moment
// Callers are returned in callers[], most recent first
//uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *cpu);

// Get up to n functions from the given stack in use at this moment
// Functions are returned in functions[], most recent first
//uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *cpu);

// NB: prog_point is c++, so beware

// Get the current program point: (Caller, PC, stack type, stack ID components)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
//void get_prog_point(CPUState *cpu, prog_point *p);

// create pandalog message for callstack info
//Panda__CallStack *pandalog_callstack_create(void);

// free that data structure
//void pandalog_callstack_free(Panda__CallStack *cs);
#endif

#ifndef PLUGIN_MAIN
// TODO: unify this macro to support a list of fn names and generate a single constructor
PPP_IMPORT(callstack_instr, on_call);
PPP_IMPORT(callstack_instr, on_ret);
#endif

