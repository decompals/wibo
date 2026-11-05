#pragma once

// Offsets for seh.S, checked against the structures below
#define CONTEXT_FLAGS 0x00
#define CONTEXT_FLOAT_SAVE 0x1c
#define CONTEXT_SEG_GS 0x8c
#define CONTEXT_SEG_FS 0x90
#define CONTEXT_SEG_ES 0x94
#define CONTEXT_SEG_DS 0x98
#define CONTEXT_EDI 0x9c
#define CONTEXT_ESI 0xa0
#define CONTEXT_EBX 0xa4
#define CONTEXT_EDX 0xa8
#define CONTEXT_ECX 0xac
#define CONTEXT_EAX 0xb0
#define CONTEXT_EBP 0xb4
#define CONTEXT_EIP 0xb8
#define CONTEXT_SEG_CS 0xbc
#define CONTEXT_EFLAGS 0xc0
#define CONTEXT_ESP 0xc4
#define CONTEXT_SEG_SS 0xc8
#define CONTEXT_EXTENDED_REGS 0xcc

#define FLOAT_SAVE_STATUS_WORD 0x04

#define RECORD_CODE 0x00
#define RECORD_FLAGS 0x04
#define RECORD_NESTED 0x08
#define RECORD_ADDRESS 0x0c
#define RECORD_NUM_PARAMS 0x10
#define RECORD_PARAMS 0x14

#define EXCEPTION_FRAME_CONTEXT 0x34
#define EXCEPTION_FRAME_RECORD 0x300
#define EXCEPTION_FRAME_SIZE 0x350

#ifndef __ASSEMBLER__

#include "kernel32/errhandlingapi.h"
#include "types.h"

// Lives on the guest stack while the loops in seh.S call the guest routines that dispatch or unwind it
struct GuestExceptionFrame {
	GUEST_PTR Arguments[4];					 // for the next routine, at the stack pointer it's called with
	EXCEPTION_REGISTRATION_RECORD Protector; // linked while a handler runs, so exceptions it raises are nested
	GUEST_PTR Registration;
	GUEST_PTR DispatcherContext;
	EXCEPTION_POINTERS Pointers;
	GUEST_PTR TargetFrame;
	GUEST_PTR NestedFrame;
	DWORD TrapNumber; // of a floating-point fault, whose details are in the saved FPU state
	CONTEXT Context;
	EXCEPTION_RECORD Record;
};

static_assert(offsetof(CONTEXT, ContextFlags) == CONTEXT_FLAGS);
static_assert(offsetof(CONTEXT, FloatSave) == CONTEXT_FLOAT_SAVE);
static_assert(offsetof(CONTEXT, SegGs) == CONTEXT_SEG_GS);
static_assert(offsetof(CONTEXT, SegFs) == CONTEXT_SEG_FS);
static_assert(offsetof(CONTEXT, SegEs) == CONTEXT_SEG_ES);
static_assert(offsetof(CONTEXT, SegDs) == CONTEXT_SEG_DS);
static_assert(offsetof(CONTEXT, Edi) == CONTEXT_EDI);
static_assert(offsetof(CONTEXT, Esi) == CONTEXT_ESI);
static_assert(offsetof(CONTEXT, Ebx) == CONTEXT_EBX);
static_assert(offsetof(CONTEXT, Edx) == CONTEXT_EDX);
static_assert(offsetof(CONTEXT, Ecx) == CONTEXT_ECX);
static_assert(offsetof(CONTEXT, Eax) == CONTEXT_EAX);
static_assert(offsetof(CONTEXT, Ebp) == CONTEXT_EBP);
static_assert(offsetof(CONTEXT, Eip) == CONTEXT_EIP);
static_assert(offsetof(CONTEXT, SegCs) == CONTEXT_SEG_CS);
static_assert(offsetof(CONTEXT, EFlags) == CONTEXT_EFLAGS);
static_assert(offsetof(CONTEXT, Esp) == CONTEXT_ESP);
static_assert(offsetof(CONTEXT, SegSs) == CONTEXT_SEG_SS);
static_assert(offsetof(CONTEXT, ExtendedRegisters) == CONTEXT_EXTENDED_REGS);
static_assert(offsetof(FLOATING_SAVE_AREA, StatusWord) == FLOAT_SAVE_STATUS_WORD);
static_assert(offsetof(EXCEPTION_RECORD, ExceptionCode) == RECORD_CODE);
static_assert(offsetof(EXCEPTION_RECORD, ExceptionFlags) == RECORD_FLAGS);
static_assert(offsetof(EXCEPTION_RECORD, ExceptionRecord) == RECORD_NESTED);
static_assert(offsetof(EXCEPTION_RECORD, ExceptionAddress) == RECORD_ADDRESS);
static_assert(offsetof(EXCEPTION_RECORD, NumberParameters) == RECORD_NUM_PARAMS);
static_assert(offsetof(EXCEPTION_RECORD, ExceptionInformation) == RECORD_PARAMS);
static_assert(offsetof(GuestExceptionFrame, Context) == EXCEPTION_FRAME_CONTEXT);
static_assert(offsetof(GuestExceptionFrame, Record) == EXCEPTION_FRAME_RECORD);
static_assert(sizeof(GuestExceptionFrame) == EXCEPTION_FRAME_SIZE);
// fxsave/fxrstor need ExtendedRegisters 16-byte aligned in a 16-byte aligned frame
static_assert((EXCEPTION_FRAME_CONTEXT + CONTEXT_EXTENDED_REGS) % 16 == 0);

namespace wibo::seh {

void install();
bool initThread();
void cleanupThread();
void *guestExport(const char *name);

} // namespace wibo::seh

#endif // __ASSEMBLER__
