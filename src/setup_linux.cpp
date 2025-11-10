#include "setup.h"

#include "common.h"

#include <asm/ldt.h>
#include <cstring>
#include <mutex>

namespace {

std::mutex g_tebSetupMutex;
int g_entryNumber = -1;

} // namespace

constexpr uint16_t createSelector(int entryNumber) {
	return static_cast<uint16_t>((entryNumber << 3) | USER_PRIVILEGE);
}

#if defined(__x86_64__)

// Implemented in setup.S
extern "C" int tebThreadSetup64(int entryNumber, TEB *teb);

bool tebThreadSetup(TEB *teb) {
	std::lock_guard guard(g_tebSetupMutex);
	int ret = tebThreadSetup64(g_entryNumber, teb);
	if (ret < 0) {
		return false;
	}
	if (g_entryNumber != ret) {
		g_entryNumber = ret;
		DEBUG_LOG("set_thread_area: allocated entry=%d base=%p\n", g_entryNumber, teb);
	} else {
		DEBUG_LOG("set_thread_area: reused entry=%d base=%p\n", g_entryNumber, teb);
	}

	teb->CurrentFsSelector = createSelector(ret);
	teb->CurrentGsSelector = 0;
	return true;
}

#elif defined(__i386__)

#include <sys/syscall.h>

bool tebThreadSetup(TEB *teb) {
	std::lock_guard guard(g_tebSetupMutex);

	struct user_desc desc; // NOLINT(cppcoreguidelines-pro-type-member-init)
	std::memset(&desc, 0, sizeof(desc));
	desc.entry_number = g_entryNumber;
	desc.base_addr = reinterpret_cast<uintptr_t>(teb);
	desc.limit = static_cast<unsigned int>(sizeof(TEB) - 1);
	desc.seg_32bit = 1;
	desc.contents = 0;
	desc.read_exec_only = 0;
	desc.limit_in_pages = 0;
	desc.seg_not_present = 0;
	desc.useable = 1;
	if (syscall(SYS_set_thread_area, &desc) != 0) {
		return false;
	}
	if (g_entryNumber != static_cast<int>(desc.entry_number)) {
		g_entryNumber = static_cast<int>(desc.entry_number);
		DEBUG_LOG("setup_linux: allocated GDT entry=%d base=%p\n", g_entryNumber, teb);
	} else {
		DEBUG_LOG("setup_linux: reused GDT entry=%d base=%p\n", g_entryNumber, teb);
	}

	teb->CurrentFsSelector = createSelector(desc.entry_number);
	teb->CurrentGsSelector = 0;
	return true;
}

#endif

bool tebThreadTeardown(TEB *teb) {
	(void)teb;
	// no-op on Linux
	return true;
}
