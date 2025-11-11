#include "setup.h"

#include "common.h"
#include "types.h"

#include <array>
#include <cstring>
#include <mutex>

#include <asm/ldt.h>
#include <sys/syscall.h>

namespace {

std::mutex g_tebSetupMutex;
int g_threadAreaEntry = -1;
#ifdef __x86_64__
uint16_t g_codeSelector = 0;
uint16_t g_dataSelector = 0;
#endif
constexpr int kMaxLdtEntries = 8192;
constexpr int kBitsPerWord = 32;
std::array<uint32_t, kMaxLdtEntries / kBitsPerWord> g_ldtBitmap{};
bool g_ldtBitmapInitialized = false;
int g_ldtHint = 0;

inline user_desc createLdtEntry(uint32_t entryNumber, uint32_t base, uint32_t size, bool code) {
	user_desc desc; // NOLINT(cppcoreguidelines-pro-type-member-init)
	// Must memset to zero to avoid uninitialized padding bytes
	std::memset(&desc, 0, sizeof(desc));

	desc.entry_number = entryNumber;
	desc.base_addr = base;

	uint32_t limit;
	if (size > 0xFFFFF) {
		// Page granularity (like your DESC_GRAN_PAGE case)
		limit = (size - 1) >> 12;
		desc.limit_in_pages = 1;
	} else {
		// Byte granularity
		limit = size - 1;
		desc.limit_in_pages = 0;
	}
	desc.limit = limit;
	desc.seg_32bit = 1;
	desc.contents = code ? MODIFY_LDT_CONTENTS_CODE : MODIFY_LDT_CONTENTS_DATA;
	desc.read_exec_only = 0;
	desc.seg_not_present = 0;
	desc.useable = 1;
	return desc;
}

inline int modifyLdtRead(struct user_desc *entries, int bytes) {
	return static_cast<int>(syscall(SYS_modify_ldt, 2, entries, bytes));
}

inline int modifyLdtWrite(const struct user_desc *desc) {
	return static_cast<int>(syscall(SYS_modify_ldt, 1, desc, sizeof(*desc)));
}

constexpr uint16_t createGdtSelector(int entryNumber) {
	return static_cast<uint16_t>((entryNumber << 3) | USER_PRIVILEGE);
}

constexpr uint16_t createLdtSelector(int entryNumber) {
	return static_cast<uint16_t>((entryNumber << 3) | 0x4 /* TI=1 */ | USER_PRIVILEGE);
}

inline bool isLdtEntryValid(int entry) { return entry >= 0 && entry < kMaxLdtEntries; }

inline void markLdtEntryUsed(int entry) {
	if (!isLdtEntryValid(entry)) {
		return;
	}
	g_ldtBitmap[entry / kBitsPerWord] |= (1u << (entry % kBitsPerWord));
}

inline void markLdtEntryFree(int entry) {
	if (!isLdtEntryValid(entry)) {
		return;
	}
	g_ldtBitmap[entry / kBitsPerWord] &= ~(1u << (entry % kBitsPerWord));
}

inline bool isLdtEntryUsed(int entry) {
	if (!isLdtEntryValid(entry)) {
		return true;
	}
	return (g_ldtBitmap[entry / kBitsPerWord] & (1u << (entry % kBitsPerWord))) != 0;
}

void initializeLdtBitmapLocked() {
	if (g_ldtBitmapInitialized) {
		return;
	}
	g_ldtBitmapInitialized = true;
	struct user_desc table[kMaxLdtEntries];
	std::memset(table, 0, sizeof(table));
	int bytes = modifyLdtRead(table, sizeof(table));
	if (bytes < 0) {
		DEBUG_LOG("setup_linux: modify_ldt(read) failed during bitmap init (%s), assuming empty table\n",
				  strerror(errno));
		return;
	}
	int count = bytes / static_cast<int>(sizeof(user_desc));
	if (count > kMaxLdtEntries) {
		DEBUG_LOG("setup_linux: modify_ldt(read) returned too many entries (%d), truncating to %d\n", count,
				  kMaxLdtEntries);
		count = kMaxLdtEntries;
	}
	for (int i = 0; i < count; ++i) {
		const user_desc &d = table[i];
		user_desc unused; // NOLINT(cppcoreguidelines-pro-type-member-init)
		std::memset(&unused, 0, sizeof(user_desc));
		bool allZero = std::memcmp(&d, &unused, sizeof(user_desc)) == 0;
		if (!allZero && !d.seg_not_present) {
			markLdtEntryUsed(i);
		}
	}
}

int allocateLdtEntryLocked() {
	initializeLdtBitmapLocked();
	auto tryAllocate = [&](int start) -> int {
		for (int entry = start; entry < kMaxLdtEntries; ++entry) {
			if (!isLdtEntryUsed(entry)) {
				markLdtEntryUsed(entry);
				g_ldtHint = entry + 1;
				if (g_ldtHint >= kMaxLdtEntries) {
					g_ldtHint = 0;
				}
				DEBUG_LOG("setup_linux: Allocating LDT entry %d\n", entry);
				return entry;
			}
		}
		return -1;
	};
	int entry = tryAllocate(g_ldtHint);
	if (entry >= 0) {
		return entry;
	}
	entry = tryAllocate(0);
	if (entry >= 0) {
		return entry;
	}
	errno = ENOSPC;
	return -1;
}

void freeLdtEntryLocked(int entryNumber) {
	if (!g_ldtBitmapInitialized || !isLdtEntryValid(entryNumber)) {
		return;
	}
	markLdtEntryFree(entryNumber);
	if (entryNumber < g_ldtHint) {
		g_ldtHint = entryNumber;
	}
}

#ifdef __x86_64__
bool segmentSetupLocked(TEB *teb) {
	// Create code LDT entry
	if (g_codeSelector == 0) {
		int entryNumber = allocateLdtEntryLocked();
		if (entryNumber < 0) {
			return false;
		}
		user_desc codeLdt = createLdtEntry(entryNumber, 0, 0xFFFFFFFF, true);
		int ret = modifyLdtWrite(&codeLdt);
		if (ret == 0) {
			g_codeSelector = createLdtSelector(entryNumber);
			DEBUG_LOG("setup_linux: Code LDT selector 0x%x\n", g_codeSelector);
		} else {
			freeLdtEntryLocked(entryNumber);
			DEBUG_LOG("setup_linux: Failed to create code LDT entry, trying default (0x23)\n");
			g_codeSelector = 0x23;
		}
	}
	// Create data LDT entry
	if (g_dataSelector == 0) {
		int entryNumber = allocateLdtEntryLocked();
		if (entryNumber < 0) {
			return false;
		}
		user_desc dataLdt = createLdtEntry(entryNumber, 0, 0xFFFFFFFF, false);
		int ret = modifyLdtWrite(&dataLdt);
		if (ret == 0) {
			g_dataSelector = createLdtSelector(entryNumber);
			DEBUG_LOG("setup_linux: Data LDT selector 0x%x\n", g_dataSelector);
		} else {
			freeLdtEntryLocked(entryNumber);
			DEBUG_LOG("setup_linux: Failed to create data LDT entry, trying default (0x2b)\n");
			g_dataSelector = 0x2b;
		}
	}
	teb->CodeSelector = g_codeSelector;
	teb->DataSelector = g_dataSelector;
	return true;
}
#endif

} // namespace

#if defined(__x86_64__)

#include <cpuid.h>

// Implemented in setup.S
extern "C" void installSelectors(TEB *teb);
extern "C" int setThreadArea64(int entryNumber, TEB *teb);

bool tebThreadSetup(TEB *teb) {
	std::lock_guard guard(g_tebSetupMutex);

	// Check for FSBASE/GSBASE instruction support
	unsigned int regs[4];
	unsigned int cpuidMax = __get_cpuid_max(0, nullptr);
	if (cpuidMax >= 0x7 && __get_cpuid_count(0x7, 0, &regs[0], &regs[1], &regs[2], &regs[3])) {
		teb->HasFsGsBase = !!(regs[1] & 1);
	}
	DEBUG_LOG("setup_linux: FSBASE/GSBASE instruction support: %s\n", teb->HasFsGsBase ? "yes" : "no");

	// Create code and data LDT entries
	if (!segmentSetupLocked(teb)) {
		return false;
	}

	// Install ds/es selectors
	installSelectors(teb);

	if (g_threadAreaEntry != -2) {
		int ret = setThreadArea64(g_threadAreaEntry, teb);
		if (ret >= 0) {
			if (g_threadAreaEntry != ret) {
				g_threadAreaEntry = ret;
				DEBUG_LOG("setup_linux: allocated thread-local GDT entry=%d base=%p\n", g_threadAreaEntry, teb);
			} else {
				DEBUG_LOG("setup_linux: reused thread-local GDT entry=%d base=%p\n", g_threadAreaEntry, teb);
			}
			teb->CurrentFsSelector = createGdtSelector(ret);
		} else {
			DEBUG_LOG("setup_linux: set_thread_area failed (%s), falling back to LDT\n", strerror(errno));
			g_threadAreaEntry = -2; // Don't bother trying again
		}
	}
	if (teb->CurrentFsSelector == 0) {
		int entryNumber = allocateLdtEntryLocked();
		if (entryNumber < 0) {
			return false;
		}
		user_desc fsLdt = createLdtEntry(entryNumber, toGuestPtr(teb), sizeof(TEB), false);
		int ret = modifyLdtWrite(&fsLdt);
		if (ret != 0) {
			freeLdtEntryLocked(entryNumber);
			return false;
		}
		teb->CurrentFsSelector = createLdtSelector(entryNumber);
	}

	DEBUG_LOG("setup_linux: Using FS selector 0x%x\n", teb->CurrentFsSelector);
	return true;
}

#elif defined(__i386__)

bool tebThreadSetup(TEB *teb) {
	std::lock_guard guard(g_tebSetupMutex);

	if (g_threadAreaEntry != -2) {
		struct user_desc desc; // NOLINT(cppcoreguidelines-pro-type-member-init)
		std::memset(&desc, 0, sizeof(desc));
		desc.entry_number = g_threadAreaEntry;
		desc.base_addr = reinterpret_cast<uintptr_t>(teb);
		desc.limit = static_cast<unsigned int>(sizeof(TEB) - 1);
		desc.seg_32bit = 1;
		desc.contents = 0;
		desc.read_exec_only = 0;
		desc.limit_in_pages = 0;
		desc.seg_not_present = 0;
		desc.useable = 1;
		if (syscall(SYS_set_thread_area, &desc) == 0) {
			if (g_threadAreaEntry != static_cast<int>(desc.entry_number)) {
				g_threadAreaEntry = static_cast<int>(desc.entry_number);
				DEBUG_LOG("setup_linux: allocated thread-local GDT entry=%d base=%p\n", g_threadAreaEntry, teb);
			} else {
				DEBUG_LOG("setup_linux: reused thread-local GDT entry=%d base=%p\n", g_threadAreaEntry, teb);
			}
			teb->CurrentFsSelector = createGdtSelector(desc.entry_number);
		} else {
			DEBUG_LOG("setup_linux: set_thread_area failed (%s), falling back to LDT\n", strerror(errno));
			g_threadAreaEntry = -2; // Don't bother trying again
		}
	}
	if (teb->CurrentFsSelector == 0) {
		int entryNumber = allocateLdtEntryLocked();
		if (entryNumber < 0) {
			return false;
		}
		user_desc fsLdt = createLdtEntry(entryNumber, toGuestPtr(teb), sizeof(TEB), false);
		int ret = modifyLdtWrite(&fsLdt);
		if (ret != 0) {
			freeLdtEntryLocked(entryNumber);
			return false;
		}
		teb->CurrentFsSelector = createLdtSelector(entryNumber);
	}

	DEBUG_LOG("setup_linux: Using FS selector 0x%x\n", teb->CurrentFsSelector);
	return true;
}

#endif

bool tebThreadTeardown(TEB *teb) {
	if (teb->CurrentFsSelector & 0x4 /* TI=1 */) {
		std::lock_guard guard(g_tebSetupMutex);
		freeLdtEntryLocked(teb->CurrentFsSelector >> 3);
	}
	teb->CurrentFsSelector = 0;
	return true;
}
