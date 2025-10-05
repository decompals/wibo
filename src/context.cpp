#include "common.h"

#include <cstddef>

namespace {

constexpr size_t kHostFsOffset = offsetof(TIB, hostFsSelector);
constexpr size_t kHostGsOffset = offsetof(TIB, hostGsSelector);
constexpr size_t kHostValidOffset = offsetof(TIB, hostSegmentsValid);
thread_local TIB *g_threadTibForHost = nullptr;

} // namespace

namespace wibo {

void setThreadTibForHost(TIB *tib) { g_threadTibForHost = tib; }

TIB *getThreadTibForHost() { return g_threadTibForHost; }

HostContextGuard::HostContextGuard() : previousFs_(0), previousGs_(0), restore_(false) {
	asm volatile("mov %%fs, %0" : "=r"(previousFs_));
	asm volatile("mov %%gs, %0" : "=r"(previousGs_));
	if (previousFs_ == wibo::tibSelector) {
		unsigned char hostValid = 0;
		asm volatile("movb %%fs:%c1, %0" : "=r"(hostValid) : "i"(kHostValidOffset));
		if (hostValid) {
			uint16_t hostFs = 0;
			uint16_t hostGs = 0;
			asm volatile("movw %%fs:%c1, %0" : "=r"(hostFs) : "i"(kHostFsOffset));
			asm volatile("movw %%fs:%c1, %0" : "=r"(hostGs) : "i"(kHostGsOffset));
			asm volatile("movw %0, %%fs" : : "r"(hostFs) : "memory");
			asm volatile("movw %0, %%gs" : : "r"(hostGs) : "memory");
			restore_ = true;
		}
	}
}

HostContextGuard::~HostContextGuard() {
	if (restore_) {
		asm volatile("movw %0, %%fs" : : "r"(previousFs_) : "memory");
		asm volatile("movw %0, %%gs" : : "r"(previousGs_) : "memory");
	}
}

GuestContextGuard::GuestContextGuard(TIB *tib) : previousFs_(0), previousGs_(0), applied_(false) {
	if (!tib || !wibo::tibSelector) {
		return;
	}
	asm volatile("mov %%fs, %0" : "=r"(previousFs_));
	asm volatile("mov %%gs, %0" : "=r"(previousGs_));
	tib->hostFsSelector = previousFs_;
	tib->hostGsSelector = previousGs_;
	tib->hostSegmentsValid = 1;
	asm volatile("movw %0, %%fs" : : "r"(wibo::tibSelector) : "memory");
	applied_ = true;
}

GuestContextGuard::~GuestContextGuard() {
	if (applied_) {
		asm volatile("movw %0, %%fs" : : "r"(previousFs_) : "memory");
		asm volatile("movw %0, %%gs" : : "r"(previousGs_) : "memory");
	}
}

} // namespace wibo
