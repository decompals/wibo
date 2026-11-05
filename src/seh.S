#include "macros.S"
#include "seh.h"

#ifdef __APPLE__
#define LOCAL(name) L##name
#else
#define LOCAL(name) .L##name
#endif

#define CONTEXT_FLAGS_FULL 0x10007     // CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
#define CONTEXT_FLAGS_ALL 0x1003f      // CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
#define CONTEXT_FLAGS_FP 0x10008       // CONTEXT_FLOATING_POINT
#define CONTEXT_FLAGS_EXTENDED 0x10020 // CONTEXT_EXTENDED_REGISTERS
#define FXSAVE_STATUS_WORD 0x02
#define TRAP_FLAG 0x100

.text
.code32

# Opens a stack frame and builds a zeroed GuestExceptionFrame at esp, holding the context that returns from the
# current stdcall function with 16 bytes of arguments. Leaves ecx pointing at the context.
.macro CAPTURE_CONTEXT flags
	push ebp
	mov ebp, esp
	pushfd                                        # [ebp-4]
	push eax                                      # [ebp-8]
	push ecx                                      # [ebp-12]
	push edx                                      # [ebp-16]
	push edi                                      # [ebp-20]
	sub esp, EXCEPTION_FRAME_SIZE
	and esp, -16
	mov edi, esp
	mov ecx, EXCEPTION_FRAME_SIZE / 4
	xor eax, eax
	cld
	rep stosd
	lea ecx, [esp+EXCEPTION_FRAME_CONTEXT]
	mov dword ptr [ecx+CONTEXT_FLAGS], \flags
	mov eax, dword ptr [ebp-4]
	mov dword ptr [ecx+CONTEXT_EFLAGS], eax
	mov eax, dword ptr [ebp-8]
	mov dword ptr [ecx+CONTEXT_EAX], eax
	mov eax, dword ptr [ebp-12]
	mov dword ptr [ecx+CONTEXT_ECX], eax
	mov eax, dword ptr [ebp-16]
	mov dword ptr [ecx+CONTEXT_EDX], eax
	mov eax, dword ptr [ebp-20]
	mov dword ptr [ecx+CONTEXT_EDI], eax
	mov dword ptr [ecx+CONTEXT_EBX], ebx
	mov dword ptr [ecx+CONTEXT_ESI], esi
	mov eax, dword ptr [ebp]
	mov dword ptr [ecx+CONTEXT_EBP], eax
	mov eax, dword ptr [ebp+4]
	mov dword ptr [ecx+CONTEXT_EIP], eax          # return address
	lea eax, [ebp+24]
	mov dword ptr [ecx+CONTEXT_ESP], eax          # caller's esp after ret 16
	mov word ptr [ecx+CONTEXT_SEG_CS], cs
	mov word ptr [ecx+CONTEXT_SEG_DS], ds
	mov word ptr [ecx+CONTEXT_SEG_ES], es
	mov word ptr [ecx+CONTEXT_SEG_FS], fs
	mov word ptr [ecx+CONTEXT_SEG_GS], gs
	mov word ptr [ecx+CONTEXT_SEG_SS], ss
.endm

# Clears the x87 exceptions that the control word at [\area] unmasks from the status word at [\area+\status],
# so loading the state doesn't raise them again
.macro DROP_UNMASKED_EXCEPTIONS area, status
	movzx eax, word ptr [\area]
	and eax, 0x3f                                 # exception masks
	or eax, 0x7f40                                # keep all but the exception summary and busy bits
	and word ptr [\area+\status], ax
.endm

# wibo_exception_dispatch
# Entered with esp at a filled-in GuestExceptionFrame; calls the routines the host picks until one doesn't return
ASM_GLOBAL(wibo_exception_dispatch, @function)
	mov ebx, esp                                  # frame
	fxsave [ebx+EXCEPTION_FRAME_CONTEXT+CONTEXT_EXTENDED_REGS]
	fnsave [ebx+EXCEPTION_FRAME_CONTEXT+CONTEXT_FLOAT_SAVE]
	# Handlers keep the x87 state, without the exceptions that would fault again
	lea edx, [ebx+EXCEPTION_FRAME_CONTEXT+CONTEXT_FLOAT_SAVE]
	mov ecx, dword ptr [edx+FLOAT_SAVE_STATUS_WORD]
	DROP_UNMASKED_EXCEPTIONS edx, FLOAT_SAVE_STATUS_WORD
	fldenv [edx]
	mov dword ptr [edx+FLOAT_SAVE_STATUS_WORD], ecx
	push ebx
	call SYMBOL_NAME(thunk_entry_beginDispatch)
LOCAL(dispatch_loop):
	call eax                                      # arguments are at the start of the frame
	mov esp, ebx
	push eax
	push ebx
	call SYMBOL_NAME(thunk_entry_continueDispatch)
	jmp LOCAL(dispatch_loop)
ASM_END(wibo_exception_dispatch)

# void wibo_restore_context(CONTEXT *context)
# Resumes a guest context; uses the 20 bytes below context->Esp
ASM_GLOBAL(wibo_restore_context, @function)
	mov ecx, dword ptr [esp+4]                    # context
	mov eax, dword ptr [ecx+CONTEXT_FLAGS]
	and eax, CONTEXT_FLAGS_EXTENDED
	cmp eax, CONTEXT_FLAGS_EXTENDED
	jne LOCAL(restore_float_save)
	lea edx, [ecx+CONTEXT_EXTENDED_REGS]
	DROP_UNMASKED_EXCEPTIONS edx, FXSAVE_STATUS_WORD
	fxrstor [edx]
LOCAL(restore_float_save):
	mov eax, dword ptr [ecx+CONTEXT_FLAGS]
	and eax, CONTEXT_FLAGS_FP
	cmp eax, CONTEXT_FLAGS_FP
	jne LOCAL(restore_integer)
	lea edx, [ecx+CONTEXT_FLOAT_SAVE]
	DROP_UNMASKED_EXCEPTIONS edx, FLOAT_SAVE_STATUS_WORD
	fnclex                                        # frstor raises pending exceptions before loading
	frstor [edx]                                  # takes precedence over the x87 part of ExtendedRegisters
LOCAL(restore_integer):
	mov edx, dword ptr [ecx+CONTEXT_ESP]
	sub edx, 20                                   # stage ecx, eax, eip, cs and eflags on the target stack
	mov eax, dword ptr [ecx+CONTEXT_ECX]
	mov dword ptr [edx], eax
	mov eax, dword ptr [ecx+CONTEXT_EAX]
	mov dword ptr [edx+4], eax
	mov eax, dword ptr [ecx+CONTEXT_EIP]
	mov dword ptr [edx+8], eax
	xor eax, eax
	mov ax, cs
	mov dword ptr [edx+12], eax
	mov eax, dword ptr [ecx+CONTEXT_EFLAGS]
	mov dword ptr [edx+16], eax
	mov ebx, dword ptr [ecx+CONTEXT_EBX]
	mov esi, dword ptr [ecx+CONTEXT_ESI]
	mov edi, dword ptr [ecx+CONTEXT_EDI]
	mov ebp, dword ptr [ecx+CONTEXT_EBP]
	mov esp, edx
	mov edx, dword ptr [ecx+CONTEXT_EDX]
	pop ecx
	pop eax
	test dword ptr [esp+8], TRAP_FLAG
	jnz LOCAL(restore_trap)
	push dword ptr [esp+8]
	popfd
	ret 8
LOCAL(restore_trap):
	iretd                                         # unlike popfd, traps only after the instruction it returns to
ASM_END(wibo_restore_context)

# void WINAPI RaiseException(DWORD code, DWORD flags, DWORD numberOfArguments, const ULONG_PTR *arguments)
# Captures the caller's context and dispatches; returns if a handler continues execution
ASM_GLOBAL(wibo_RaiseException, @function)
	CAPTURE_CONTEXT CONTEXT_FLAGS_ALL
	lea edx, [esp+EXCEPTION_FRAME_RECORD]
	mov eax, dword ptr [ebp+8]
	mov dword ptr [edx+RECORD_CODE], eax
	mov eax, dword ptr [ebp+12]
	and eax, 1                                    # EXCEPTION_NONCONTINUABLE
	mov dword ptr [edx+RECORD_FLAGS], eax
	mov eax, dword ptr [ebp+4]
	mov dword ptr [edx+RECORD_ADDRESS], eax
	mov esi, dword ptr [ebp+20]                   # arguments
	mov ecx, dword ptr [ebp+16]                   # numberOfArguments
	test esi, esi
	jnz LOCAL(raise_clamp_arguments)
	xor ecx, ecx
LOCAL(raise_clamp_arguments):
	cmp ecx, 15                                   # EXCEPTION_MAXIMUM_PARAMETERS
	jbe LOCAL(raise_copy_arguments)
	mov ecx, 15
LOCAL(raise_copy_arguments):
	mov dword ptr [edx+RECORD_NUM_PARAMS], ecx
	lea edi, [edx+RECORD_PARAMS]
	rep movsd
	jmp SYMBOL_NAME(wibo_exception_dispatch)
ASM_END(wibo_RaiseException)

# void wibo_raise_status(NTSTATUS status, EXCEPTION_RECORD *record)
# Raises the dispatcher's own errors as noncontinuable exceptions that point at the record being handled
ASM_GLOBAL(wibo_raise_status, @function)
	CAPTURE_CONTEXT CONTEXT_FLAGS_ALL
	lea edx, [esp+EXCEPTION_FRAME_RECORD]
	mov eax, dword ptr [ebp+8]
	mov dword ptr [edx+RECORD_CODE], eax
	mov dword ptr [edx+RECORD_FLAGS], 1           # EXCEPTION_NONCONTINUABLE
	mov eax, dword ptr [ebp+12]
	mov dword ptr [edx+RECORD_NESTED], eax
	mov eax, dword ptr [ebp+4]
	mov dword ptr [edx+RECORD_ADDRESS], eax
	jmp SYMBOL_NAME(wibo_exception_dispatch)
ASM_END(wibo_raise_status)

# void WINAPI RtlUnwind(PVOID targetFrame, PVOID targetIp, PEXCEPTION_RECORD record, PVOID returnValue)
# Calls the unwind handlers above targetFrame, then resumes the caller with eax = returnValue (x86 ignores targetIp)
ASM_GLOBAL(wibo_RtlUnwind, @function)
	CAPTURE_CONTEXT CONTEXT_FLAGS_FULL
	mov eax, dword ptr [ebp+20]                   # returnValue
	mov dword ptr [ecx+CONTEXT_EAX], eax
	mov ebx, esp                                  # frame
	push dword ptr [ebp+16]                       # record
	push dword ptr [ebp+8]                        # targetFrame
	push ebx
	call SYMBOL_NAME(thunk_entry_beginUnwind)
LOCAL(unwind_loop):
	call eax                                      # arguments are at the start of the frame
	mov esp, ebx
	push eax
	push ebx
	call SYMBOL_NAME(thunk_entry_continueUnwind)
	jmp LOCAL(unwind_loop)
ASM_END(wibo_RtlUnwind)
