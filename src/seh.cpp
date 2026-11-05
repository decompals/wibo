#include "seh.h"

#include "common.h"
#include "entry.h"
#include "entry_trampolines.h"
#include "kernel32.h"
#include "kernel32/internal.h"

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/ucontext.h>
#endif

// Implemented in seh.S
extern "C" {
void wibo_exception_dispatch();
void wibo_restore_context();
void wibo_raise_status();
void wibo_RaiseException();
void wibo_RtlUnwind();
}

namespace {

thread_local void *t_altStack = nullptr;
thread_local size_t t_altStackSize = 0;

uintptr_t g_pageSize = 4096;
uint16_t g_hostCodeSelector = 0;

// wibo_restore_context stages registers just below the esp it resumes at
constexpr uint32_t kRestoreStagingSize = 20;
// The dispatcher's calls into the host push this much below the exception frame, partly from host code
constexpr uint32_t kDispatchCallSize = 64;

constexpr uint32_t kTrapFlag = 0x100;
constexpr uint32_t kDirectionFlag = 0x400;
constexpr uint32_t kAlignmentCheckFlag = 0x40000;

constexpr uint32_t kTrapDebug = 1;
constexpr uint32_t kTrapBreakpoint = 3;
constexpr uint32_t kTrapOverflow = 4;
constexpr uint32_t kTrapBoundRange = 5;
constexpr uint32_t kTrapStackFault = 12;
constexpr uint32_t kTrapPageFault = 14;
constexpr uint32_t kTrapX87 = 16;
constexpr uint32_t kTrapSimd = 19;
constexpr uint32_t kPageFaultWrite = 0x2;
constexpr uint32_t kPageFaultInstructionFetch = 0x10;

template <typename T> GUEST_PTR guestRoutine(T *routine) { return toGuestPtr(reinterpret_cast<const void *>(routine)); }

bool isValidRegistration(const TEB *teb, GUEST_PTR registration) {
	return (registration & 3) == 0 && registration >= teb->Tib.StackLimit &&
		   registration <= teb->Tib.StackBase - sizeof(EXCEPTION_REGISTRATION_RECORD) &&
		   fromGuestPtr<EXCEPTION_REGISTRATION_RECORD>(registration)->Handler != GUEST_NULL;
}

void linkProtector(TEB *teb, GuestExceptionFrame *frame, GUEST_PTR registration, GUEST_PTR protector) {
	frame->Registration = registration;
	frame->DispatcherContext = GUEST_NULL;
	frame->Protector.Next = teb->Tib.ExceptionList;
	frame->Protector.Handler = protector;
	teb->Tib.ExceptionList = toGuestPtr(&frame->Protector);
}

void unlinkProtector(TEB *teb, GuestExceptionFrame *frame) {
	if (teb->Tib.ExceptionList == toGuestPtr(&frame->Protector)) {
		teb->Tib.ExceptionList = frame->Protector.Next;
	}
}

// The loops in seh.S call the routine these return with the frame's Arguments

GUEST_PTR callHandler(TEB *teb, GuestExceptionFrame *frame, GUEST_PTR registration, GUEST_PTR protector) {
	linkProtector(teb, frame, registration, protector);
	frame->Arguments[0] = frame->Pointers.ExceptionRecord;
	frame->Arguments[1] = registration;
	frame->Arguments[2] = frame->Pointers.ContextRecord;
	frame->Arguments[3] = toGuestPtr(&frame->DispatcherContext);
	return fromGuestPtr<EXCEPTION_REGISTRATION_RECORD>(registration)->Handler;
}

GUEST_PTR resumeContext(GuestExceptionFrame *frame) {
	frame->Arguments[0] = frame->Pointers.ContextRecord;
	return guestRoutine(&wibo_restore_context);
}

GUEST_PTR raiseStatus(GuestExceptionFrame *frame, DWORD status) {
	DEBUG_LOG("seh: raising %#x\n", status);
	frame->Arguments[0] = status;
	frame->Arguments[1] = frame->Pointers.ExceptionRecord;
	return guestRoutine(&wibo_raise_status);
}

GUEST_PTR continueExecution(GuestExceptionFrame *frame) {
	if (frame->Record.ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
		return raiseStatus(frame, STATUS_NONCONTINUABLE_EXCEPTION);
	}
	return resumeContext(frame);
}

GUEST_PTR nextDispatchStep(TEB *teb, GuestExceptionFrame *frame, GUEST_PTR registration) {
	if (registration != EXCEPTION_CHAIN_END && !isValidRegistration(teb, registration)) {
		DEBUG_LOG("seh: invalid registration %#x\n", registration);
		frame->Record.ExceptionFlags |= EXCEPTION_STACK_INVALID;
		registration = EXCEPTION_CHAIN_END;
	}
	if (registration == EXCEPTION_CHAIN_END) {
		// Exceptions no frame handles go where the outermost frame of a Windows thread sends them
		linkProtector(teb, frame, EXCEPTION_CHAIN_END, guestRoutine(&thunk_entry_dispatchProtector));
		frame->Arguments[0] = toGuestPtr(&frame->Pointers);
		return guestRoutine(&thunk_kernel32_UnhandledExceptionFilter);
	}
	return callHandler(teb, frame, registration, guestRoutine(&thunk_entry_dispatchProtector));
}

GUEST_PTR nextUnwindStep(TEB *teb, GuestExceptionFrame *frame, GUEST_PTR registration) {
	if (registration == frame->TargetFrame || registration == EXCEPTION_CHAIN_END) {
		return resumeContext(frame);
	}
	if (frame->TargetFrame != GUEST_NULL && frame->TargetFrame < registration) {
		return raiseStatus(frame, STATUS_INVALID_UNWIND_TARGET);
	}
	if (!isValidRegistration(teb, registration)) {
		return raiseStatus(frame, STATUS_BAD_STACK);
	}
	return callHandler(teb, frame, registration, guestRoutine(&thunk_entry_unwindProtector));
}

// The dispatcher saves the FPU state after the signal handler, so floating-point details come from here
void describeFloatingPointFault(GuestExceptionFrame *frame) {
	EXCEPTION_RECORD &record = frame->Record;
	const CONTEXT &context = frame->Context;
	if (frame->TrapNumber == kTrapX87) {
		const FLOATING_SAVE_AREA &fpu = context.FloatSave;
		DWORD status = fpu.StatusWord & ~(fpu.ControlWord & 0x3f);
		if (status & 0x01) {
			record.ExceptionCode = (status & 0x40) ? EXCEPTION_FLT_STACK_CHECK : EXCEPTION_FLT_INVALID_OPERATION;
		} else if (status & 0x02) {
			record.ExceptionCode = EXCEPTION_FLT_DENORMAL_OPERAND;
		} else if (status & 0x04) {
			record.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
		} else if (status & 0x08) {
			record.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
		} else if (status & 0x10) {
			record.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
		} else if (status & 0x20) {
			record.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
		}
		// x87 exceptions surface at the next floating-point instruction
		record.ExceptionAddress = fpu.ErrorOffset;
	} else if (frame->TrapNumber == kTrapSimd) {
		DWORD mxcsr;
		std::memcpy(&mxcsr, context.ExtendedRegisters + 24, sizeof(mxcsr));
		record.NumberParameters = 2;
		record.ExceptionInformation[0] = 0;
		record.ExceptionInformation[1] = mxcsr;
	}
}

[[noreturn]] void exitUnhandled(DWORD code) {
	// Only the exit code's low byte reaches the parent, and it must not read as success
	kernel32::exitInternal((code & 0xff) != 0 ? code : 1);
}

#if defined(__linux__)

// libc may touch host TLS, which isn't loaded while guest code runs
long rawSyscall(long number, long arg1 = 0, long arg2 = 0, long arg3 = 0, long arg4 = 0) {
	long result;
#if defined(__x86_64__)
	register long r10 asm("r10") = arg4;
	asm volatile("syscall"
				 : "=a"(result)
				 : "0"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
				 : "rcx", "r11", "memory");
#else
	asm volatile("xchg %%edi, %%ebx\n\t"
				 "int $0x80\n\t"
				 "xchg %%edi, %%ebx"
				 : "=a"(result)
				 : "0"(number), "D"(arg1), "c"(arg2), "d"(arg3), "S"(arg4)
				 : "memory");
#endif
	return result;
}

void resetSignal(int sig) {
	struct {
		uintptr_t handler;
		unsigned long flags;
		uintptr_t restorer;
		uint64_t mask;
	} action = {};
	rawSyscall(SYS_rt_sigaction, sig, reinterpret_cast<long>(&action), 0, sizeof(action.mask));
}

void raiseSignal(int sig) { rawSyscall(SYS_kill, rawSyscall(SYS_getpid), sig); }

bool makeWritable(uint32_t address, size_t size) {
	return rawSyscall(SYS_mprotect, static_cast<long>(address), static_cast<long>(size), PROT_READ | PROT_WRITE) == 0;
}

#else

void resetSignal(int sig) { signal(sig, SIG_DFL); }

void raiseSignal(int sig) { raise(sig); }

bool makeWritable(uint32_t address, size_t size) {
	return mprotect(reinterpret_cast<void *>(static_cast<uintptr_t>(address)), size, PROT_READ | PROT_WRITE) == 0;
}

#endif

struct GuestRegisters {
	uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, eflags;
	uint32_t cs, ds, es, fs, gs, ss;
	uint32_t trapNumber, errorCode;
};

#if defined(__linux__) && defined(__i386__)

bool isKernelSignal(const siginfo_t *info) { return info->si_code > 0; }

// The host never loads fs on i386
bool isGuestCode(const ucontext_t *uc) { return (uc->uc_mcontext.gregs[REG_FS] & 0xffff) != 0; }

void loadRegisters(const ucontext_t *uc, GuestRegisters &regs) {
	const greg_t *g = uc->uc_mcontext.gregs;
	regs.eax = g[REG_EAX];
	regs.ecx = g[REG_ECX];
	regs.edx = g[REG_EDX];
	regs.ebx = g[REG_EBX];
	regs.esp = g[REG_ESP];
	regs.ebp = g[REG_EBP];
	regs.esi = g[REG_ESI];
	regs.edi = g[REG_EDI];
	regs.eip = g[REG_EIP];
	regs.eflags = g[REG_EFL];
	regs.cs = g[REG_CS] & 0xffff;
	regs.ds = g[REG_DS] & 0xffff;
	regs.es = g[REG_ES] & 0xffff;
	regs.fs = g[REG_FS] & 0xffff;
	regs.gs = g[REG_GS] & 0xffff;
	regs.ss = g[REG_SS] & 0xffff;
	regs.trapNumber = g[REG_TRAPNO];
	regs.errorCode = g[REG_ERR];
}

void storeControl(ucontext_t *uc, const GuestRegisters &regs) {
	uc->uc_mcontext.gregs[REG_EIP] = static_cast<greg_t>(regs.eip);
	uc->uc_mcontext.gregs[REG_ESP] = static_cast<greg_t>(regs.esp); // sigreturn reads sc->sp, not sp_at_signal
	uc->uc_mcontext.gregs[REG_EFL] = static_cast<greg_t>(regs.eflags);
}

#elif defined(__linux__) && defined(__x86_64__)

bool isKernelSignal(const siginfo_t *info) { return info->si_code > 0; }

bool isGuestCode(const ucontext_t *uc) { return (uc->uc_mcontext.gregs[REG_CSGSFS] & 0xffff) != g_hostCodeSelector; }

void loadRegisters(const ucontext_t *uc, GuestRegisters &regs) {
	const greg_t *g = uc->uc_mcontext.gregs;
	regs.eax = g[REG_RAX];
	regs.ecx = g[REG_RCX];
	regs.edx = g[REG_RDX];
	regs.ebx = g[REG_RBX];
	regs.esp = g[REG_RSP];
	regs.ebp = g[REG_RBP];
	regs.esi = g[REG_RSI];
	regs.edi = g[REG_RDI];
	regs.eip = g[REG_RIP];
	regs.eflags = g[REG_EFL];
	// 64-bit signal frames leave the data segment registers alone
	uint16_t selector;
	asm volatile("mov %%ds, %0" : "=r"(selector));
	regs.ds = selector;
	asm volatile("mov %%es, %0" : "=r"(selector));
	regs.es = selector;
	asm volatile("mov %%fs, %0" : "=r"(selector));
	regs.fs = selector;
	asm volatile("mov %%gs, %0" : "=r"(selector));
	regs.gs = selector;
	regs.cs = g[REG_CSGSFS] & 0xffff;
	regs.ss = (g[REG_CSGSFS] >> 48) & 0xffff;
	regs.trapNumber = g[REG_TRAPNO];
	regs.errorCode = g[REG_ERR];
}

void storeControl(ucontext_t *uc, const GuestRegisters &regs) {
	uc->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(regs.eip);
	uc->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(regs.esp);
	uc->uc_mcontext.gregs[REG_EFL] = static_cast<greg_t>(regs.eflags);
}

#elif defined(__APPLE__) && defined(__x86_64__)

// General protection faults arrive with si_code 0
bool isKernelSignal(const siginfo_t *info) { return info->si_code < SI_USER; }

bool isGuestCode(const ucontext_t *uc) { return (uc->uc_mcontext->__ss.__cs & 0xffff) != g_hostCodeSelector; }

void loadRegisters(const ucontext_t *uc, GuestRegisters &regs) {
	const auto &ss = uc->uc_mcontext->__ss;
	regs.eax = ss.__rax;
	regs.ecx = ss.__rcx;
	regs.edx = ss.__rdx;
	regs.ebx = ss.__rbx;
	regs.esp = ss.__rsp;
	regs.ebp = ss.__rbp;
	regs.esi = ss.__rsi;
	regs.edi = ss.__rdi;
	regs.eip = ss.__rip;
	regs.eflags = ss.__rflags;
	regs.cs = ss.__cs & 0xffff;
	regs.fs = ss.__fs & 0xffff;
	regs.gs = ss.__gs & 0xffff;
	uint16_t selector;
	asm volatile("mov %%ds, %0" : "=r"(selector));
	regs.ds = selector;
	asm volatile("mov %%es, %0" : "=r"(selector));
	regs.es = selector;
	asm volatile("mov %%ss, %0" : "=r"(selector));
	regs.ss = selector;
	regs.trapNumber = uc->uc_mcontext->__es.__trapno;
	regs.errorCode = uc->uc_mcontext->__es.__err;
}

void storeControl(ucontext_t *uc, const GuestRegisters &regs) {
	uc->uc_mcontext->__ss.__rip = regs.eip;
	uc->uc_mcontext->__ss.__rsp = regs.esp;
	uc->uc_mcontext->__ss.__rflags = regs.eflags;
}

#else
#error "Unsupported platform"
#endif

TEB *currentGuestTeb() {
#if defined(__APPLE__)
	uint64_t teb;
	asm volatile("mov %%gs:0x30, %0" : "=r"(teb)); // TSD slot set in setup_darwin.cpp
	return reinterpret_cast<TEB *>(teb);
#else
	uint32_t teb;
	asm volatile("movl %%fs:%c1, %0" : "=r"(teb) : "i"(TEB_SELF));
	return reinterpret_cast<TEB *>(static_cast<uintptr_t>(teb));
#endif
}

DWORD floatingPointCode(int siCode) {
	switch (siCode) {
	case FPE_FLTDIV:
		return EXCEPTION_FLT_DIVIDE_BY_ZERO;
	case FPE_FLTOVF:
		return EXCEPTION_FLT_OVERFLOW;
	case FPE_FLTUND:
		return EXCEPTION_FLT_UNDERFLOW;
	case FPE_FLTRES:
		return EXCEPTION_FLT_INEXACT_RESULT;
	default:
		return EXCEPTION_FLT_INVALID_OPERATION;
	}
}

bool describeFault(int sig, const siginfo_t *info, GuestRegisters &regs, GuestExceptionFrame *frame) {
	EXCEPTION_RECORD &record = frame->Record;
	switch (sig) {
	case SIGSEGV:
	case SIGBUS:
		switch (regs.trapNumber) {
		case kTrapOverflow:
			record.ExceptionCode = EXCEPTION_INT_OVERFLOW;
			return true;
		case kTrapBoundRange:
			record.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
			return true;
		case kTrapStackFault:
			record.ExceptionCode = EXCEPTION_STACK_OVERFLOW;
			return true;
		case kTrapPageFault:
			record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
			record.NumberParameters = 2;
			if (regs.errorCode & kPageFaultInstructionFetch) {
				record.ExceptionInformation[0] = 8;
			} else if (regs.errorCode & kPageFaultWrite) {
				record.ExceptionInformation[0] = 1;
			}
			record.ExceptionInformation[1] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(info->si_addr));
			return true;
		default:
			// Protection faults don't report an address
			record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
			record.NumberParameters = 2;
			record.ExceptionInformation[1] = 0xFFFFFFFF;
			return true;
		}
	case SIGILL:
		record.ExceptionCode = (info->si_code == ILL_PRVOPC || info->si_code == ILL_PRVREG)
								   ? EXCEPTION_PRIV_INSTRUCTION
								   : EXCEPTION_ILLEGAL_INSTRUCTION;
		return true;
	case SIGFPE:
		frame->TrapNumber = regs.trapNumber;
		if (info->si_code == FPE_INTDIV) {
			record.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
		} else if (info->si_code == FPE_INTOVF) {
			record.ExceptionCode = EXCEPTION_INT_OVERFLOW;
		} else if (regs.trapNumber == kTrapSimd) {
			bool fault = info->si_code == FPE_FLTOVF || info->si_code == FPE_FLTUND || info->si_code == FPE_FLTRES;
			record.ExceptionCode = fault ? STATUS_FLOAT_MULTIPLE_FAULTS : STATUS_FLOAT_MULTIPLE_TRAPS;
		} else {
			record.ExceptionCode = floatingPointCode(info->si_code);
		}
		return true;
	case SIGTRAP:
		if (regs.trapNumber == kTrapBoundRange) {
			record.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED; // macOS sends #BR as SIGTRAP
		} else if (regs.trapNumber == kTrapDebug) {
			record.ExceptionCode = EXCEPTION_SINGLE_STEP;
			regs.eflags &= ~kTrapFlag;
		} else {
			record.ExceptionCode = EXCEPTION_BREAKPOINT;
			record.NumberParameters = 1;
			if (regs.trapNumber == kTrapBreakpoint) {
				regs.eip -= 1; // int3 reports the instruction after it
			}
		}
		return true;
	default:
		return false;
	}
}

bool redirectToDispatcher(int sig, const siginfo_t *info, TEB *teb, GuestRegisters &regs) {
	uint32_t frameAddress = (regs.esp - kRestoreStagingSize - sizeof(GuestExceptionFrame)) & ~15u;
	if (frameAddress > regs.esp) {
		return false;
	}
	// Like Windows, the first fault or exception frame to reach the guard page is a stack overflow, which commits the
	// page for the handlers
	auto faultAddress = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(info->si_addr));
	bool onThreadStack = regs.esp > teb->DeallocationStack && regs.esp <= teb->Tib.StackBase;
	uint32_t guard = teb->Tib.StackLimit - g_pageSize;
	bool faultOnGuard = (sig == SIGSEGV || sig == SIGBUS) && regs.trapNumber == kTrapPageFault &&
						faultAddress >= guard && faultAddress < teb->Tib.StackLimit;
	bool frameOnGuard = onThreadStack && frameAddress - kDispatchCallSize < teb->Tib.StackLimit;
	bool stackOverflow = guard > teb->DeallocationStack && (faultOnGuard || frameOnGuard);
	// Commit nothing unless the frame fits, so a fault that can't be dispatched happens again
	uint32_t limit = stackOverflow ? guard : teb->Tib.StackLimit;
	if (onThreadStack && frameAddress - kDispatchCallSize < limit) {
		return false;
	}
	if (stackOverflow) {
		if (!makeWritable(guard, g_pageSize)) {
			return false;
		}
		teb->Tib.StackLimit = guard;
	}
	auto *frame = reinterpret_cast<GuestExceptionFrame *>(static_cast<uintptr_t>(frameAddress));
	// volatile keeps the compiler from turning this into a memset call
	auto *words = reinterpret_cast<volatile uint32_t *>(frame);
	for (size_t i = 0; i < sizeof(GuestExceptionFrame) / sizeof(uint32_t); ++i) {
		words[i] = 0;
	}
	if (!describeFault(sig, info, regs, frame)) {
		return false;
	}
	if (stackOverflow) {
		frame->Record.ExceptionCode = EXCEPTION_STACK_OVERFLOW;
		frame->TrapNumber = 0; // not a floating-point fault any more
	}
	frame->Record.ExceptionAddress = regs.eip;

	CONTEXT &context = frame->Context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS;
	context.Eax = regs.eax;
	context.Ecx = regs.ecx;
	context.Edx = regs.edx;
	context.Ebx = regs.ebx;
	context.Esp = regs.esp;
	context.Ebp = regs.ebp;
	context.Esi = regs.esi;
	context.Edi = regs.edi;
	context.Eip = regs.eip;
	context.EFlags = regs.eflags;
	context.SegCs = regs.cs;
	context.SegDs = regs.ds;
	context.SegEs = regs.es;
	context.SegFs = regs.fs;
	context.SegGs = regs.gs;
	context.SegSs = regs.ss;

	regs.esp = frameAddress;
	regs.eip = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&wibo_exception_dispatch));
	regs.eflags &= ~(kTrapFlag | kDirectionFlag | kAlignmentCheckFlag);
	return true;
}

// Guest faults arrive with guest segments loaded, so the handler avoids host TLS
void handleSignal(int sig, siginfo_t *info, void *ucontext) {
	auto *uc = static_cast<ucontext_t *>(ucontext);
	if (isKernelSignal(info) && isGuestCode(uc)) {
		TEB *teb = currentGuestTeb();
		if (teb && teb->Tib.Self == static_cast<GUEST_PTR>(reinterpret_cast<uintptr_t>(teb))) {
			GuestRegisters regs; // NOLINT(cppcoreguidelines-pro-type-member-init)
			loadRegisters(uc, regs);
			if (redirectToDispatcher(sig, info, teb, regs)) {
				storeControl(uc, regs);
				return;
			}
		}
	}
	// Faults happen again with the default action; traps and sent signals have to be raised again
	resetSignal(sig);
	if (sig == SIGTRAP || !isKernelSignal(info)) {
		raiseSignal(sig);
	}
}

} // namespace

namespace entry {

GUEST_PTR WINAPI beginDispatch(GUEST_PTR frame) {
	TEB *teb = currentThreadTeb;
	auto *exceptionFrame = fromGuestPtr<GuestExceptionFrame>(frame);
	exceptionFrame->Pointers.ExceptionRecord = toGuestPtr(&exceptionFrame->Record);
	exceptionFrame->Pointers.ContextRecord = toGuestPtr(&exceptionFrame->Context);
	describeFloatingPointFault(exceptionFrame);
	const EXCEPTION_RECORD &record = exceptionFrame->Record;
	DEBUG_LOG("seh: dispatching exception %#x at %#x (flags %#x, params %u: %#x %#x)\n", record.ExceptionCode,
			  record.ExceptionAddress, record.ExceptionFlags, record.NumberParameters, record.ExceptionInformation[0],
			  record.ExceptionInformation[1]);
	return nextDispatchStep(teb, exceptionFrame, teb->Tib.ExceptionList);
}

GUEST_PTR WINAPI continueDispatch(GUEST_PTR frame, LONG disposition) {
	TEB *teb = currentThreadTeb;
	auto *exceptionFrame = fromGuestPtr<GuestExceptionFrame>(frame);
	EXCEPTION_RECORD &record = exceptionFrame->Record;
	unlinkProtector(teb, exceptionFrame);
	GUEST_PTR registration = exceptionFrame->Registration;
	DEBUG_LOG("seh: handler for frame %#x returned %d\n", registration, disposition);
	if (registration == EXCEPTION_CHAIN_END) {
		if (disposition != EXCEPTION_CONTINUE_EXECUTION) {
			exitUnhandled(record.ExceptionCode);
		}
		return continueExecution(exceptionFrame);
	}
	if (registration == exceptionFrame->NestedFrame) {
		record.ExceptionFlags &= ~EXCEPTION_NESTED_CALL;
		exceptionFrame->NestedFrame = GUEST_NULL;
	}
	switch (disposition) {
	case ExceptionContinueExecution:
		return continueExecution(exceptionFrame);
	case ExceptionContinueSearch:
		break;
	case ExceptionNestedException:
		// Frames up to the one whose handler raised have seen the exception that is still being handled
		record.ExceptionFlags |= EXCEPTION_NESTED_CALL;
		exceptionFrame->NestedFrame = std::max(exceptionFrame->NestedFrame, exceptionFrame->DispatcherContext);
		break;
	default:
		return raiseStatus(exceptionFrame, STATUS_INVALID_DISPOSITION);
	}
	return nextDispatchStep(teb, exceptionFrame, fromGuestPtr<EXCEPTION_REGISTRATION_RECORD>(registration)->Next);
}

GUEST_PTR WINAPI beginUnwind(GUEST_PTR frame, GUEST_PTR targetFrame, GUEST_PTR exceptionRecord) {
	TEB *teb = currentThreadTeb;
	auto *exceptionFrame = fromGuestPtr<GuestExceptionFrame>(frame);
	if (exceptionRecord == GUEST_NULL) {
		exceptionFrame->Record.ExceptionCode = STATUS_UNWIND;
		exceptionFrame->Record.ExceptionAddress = exceptionFrame->Context.Eip;
		exceptionRecord = toGuestPtr(&exceptionFrame->Record);
	}
	auto *record = fromGuestPtr<EXCEPTION_RECORD>(exceptionRecord);
	record->ExceptionFlags |= EXCEPTION_UNWINDING;
	if (targetFrame == GUEST_NULL) {
		record->ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
	}
	exceptionFrame->Pointers.ExceptionRecord = exceptionRecord;
	exceptionFrame->Pointers.ContextRecord = toGuestPtr(&exceptionFrame->Context);
	exceptionFrame->TargetFrame = targetFrame;
	DEBUG_LOG("seh: unwinding to frame %#x (exception %#x)\n", targetFrame, record->ExceptionCode);
	return nextUnwindStep(teb, exceptionFrame, teb->Tib.ExceptionList);
}

GUEST_PTR WINAPI continueUnwind(GUEST_PTR frame, LONG disposition) {
	TEB *teb = currentThreadTeb;
	auto *exceptionFrame = fromGuestPtr<GuestExceptionFrame>(frame);
	unlinkProtector(teb, exceptionFrame);
	GUEST_PTR registration = exceptionFrame->Registration;
	switch (disposition) {
	case ExceptionContinueSearch:
		break;
	case ExceptionCollidedUnwind:
		// This unwind reached the handler an outer unwind is running, so it carries on from that one's frame
		registration = exceptionFrame->DispatcherContext;
		if (!isValidRegistration(teb, registration)) {
			return raiseStatus(exceptionFrame, STATUS_BAD_STACK);
		}
		break;
	default:
		return raiseStatus(exceptionFrame, STATUS_INVALID_DISPOSITION);
	}
	GUEST_PTR next = fromGuestPtr<EXCEPTION_REGISTRATION_RECORD>(registration)->Next;
	teb->Tib.ExceptionList = next;
	return nextUnwindStep(teb, exceptionFrame, next);
}

// The protectors find the frame they belong to from their registration
LONG CDECL dispatchProtector(GUEST_PTR exceptionRecord, GUEST_PTR establisherFrame, GUEST_PTR /*contextRecord*/,
							 GUEST_PTR dispatcherContext) {
	if (fromGuestPtr<EXCEPTION_RECORD>(exceptionRecord)->ExceptionFlags &
		(EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
		return ExceptionContinueSearch;
	}
	const auto *frame = fromGuestPtr<GuestExceptionFrame>(establisherFrame - offsetof(GuestExceptionFrame, Protector));
	DEBUG_LOG("seh: exception raised by the handler for frame %#x\n", frame->Registration);
	*fromGuestPtr<GUEST_PTR>(dispatcherContext) = frame->Registration;
	return ExceptionNestedException;
}

LONG CDECL unwindProtector(GUEST_PTR exceptionRecord, GUEST_PTR establisherFrame, GUEST_PTR /*contextRecord*/,
						   GUEST_PTR dispatcherContext) {
	if (!(fromGuestPtr<EXCEPTION_RECORD>(exceptionRecord)->ExceptionFlags &
		  (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND))) {
		return ExceptionContinueSearch;
	}
	const auto *frame = fromGuestPtr<GuestExceptionFrame>(establisherFrame - offsetof(GuestExceptionFrame, Protector));
	DEBUG_LOG("seh: unwind collided with the unwind handler for frame %#x\n", frame->Registration);
	*fromGuestPtr<GUEST_PTR>(dispatcherContext) = frame->Registration;
	return ExceptionCollidedUnwind;
}

} // namespace entry

namespace wibo::seh {

void install() {
	g_pageSize = static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
	asm volatile("mov %%cs, %0" : "=r"(g_hostCodeSelector));

	struct sigaction action = {};
	action.sa_sigaction = handleSignal;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&action.sa_mask);
	for (int sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP}) {
		sigaction(sig, &action, nullptr);
	}
}

bool initThread() {
	if (t_altStack) {
		return true;
	}
	size_t size = std::max<size_t>(SIGSTKSZ, 64 * 1024);
	void *stack = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		return false;
	}
	stack_t ss = {};
	ss.ss_sp = stack;
	ss.ss_size = size;
	if (sigaltstack(&ss, nullptr) != 0) {
		munmap(stack, size);
		return false;
	}
	t_altStack = stack;
	t_altStackSize = size;
	return true;
}

void cleanupThread() {
	if (!t_altStack) {
		return;
	}
	stack_t ss = {};
	ss.ss_flags = SS_DISABLE;
	sigaltstack(&ss, nullptr);
	munmap(t_altStack, t_altStackSize);
	t_altStack = nullptr;
	t_altStackSize = 0;
}

void *guestExport(const char *name) {
	if (strcmp(name, "RaiseException") == 0) {
		return reinterpret_cast<void *>(&wibo_RaiseException);
	}
	if (strcmp(name, "RtlUnwind") == 0) {
		return reinterpret_cast<void *>(&wibo_RtlUnwind);
	}
	return nullptr;
}

} // namespace wibo::seh
