#include "common.h"

#include <cstddef>

namespace wibo {

WinApiSegmentScope::WinApiSegmentScope()
	: previousFs_(0), previousGs_(0), restore_(false) {
	asm volatile("mov %%fs, %0" : "=r"(previousFs_));
	asm volatile("mov %%gs, %0" : "=r"(previousGs_));
	if (previousFs_ == wibo::tibSelector) {
		constexpr size_t kHostFsOffset = offsetof(TIB, hostFsSelector);
		constexpr size_t kHostGsOffset = offsetof(TIB, hostGsSelector);
		constexpr size_t kHostValidOffset = offsetof(TIB, hostSegmentsValid);
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

WinApiSegmentScope::~WinApiSegmentScope() {
	if (restore_) {
		asm volatile("movw %0, %%fs" : : "r"(previousFs_) : "memory");
		asm volatile("movw %0, %%gs" : : "r"(previousGs_) : "memory");
	}
}

} // namespace wibo
