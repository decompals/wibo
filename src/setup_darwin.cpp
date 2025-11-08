#include "common.h"
#include "setup.h"

#include "types.h"

#include <cerrno>
#include <cstdint>

#include <architecture/i386/table.h>
#include <i386/user_ldt.h>

// https://github.com/apple/darwin-libpthread/blob/03c4628c8940cca6fd6a82957f683af804f62e7f/private/tsd_private.h#L92-L97
#define _PTHREAD_TSD_SLOT_RESERVED_WIN64 6

#define USER_PRIVILEGE 3

namespace {

inline ldt_entry createLdtEntry(uint32_t base, uint32_t size, bool code) {
	uint32_t limit;
	uint8_t granular;
	if (size > 0xFFFFF) {
		limit = (size - 1) >> 12;
		granular = DESC_GRAN_PAGE;
	} else {
		limit = size - 1;
		granular = DESC_GRAN_BYTE;
	}
	ldt_entry entry; // NOLINT(cppcoreguidelines-pro-type-member-init)
	// Must memset to zero to avoid uninitialized padding bytes
	std::memset(&entry, 0, sizeof(ldt_entry));
	entry.code.limit00 = static_cast<uint16_t>(limit);
	entry.code.base00 = static_cast<uint16_t>(base);
	entry.code.base16 = static_cast<uint8_t>(base >> 16);
	entry.code.type = code ? DESC_CODE_READ : DESC_DATA_WRITE;
	entry.code.dpl = USER_PRIVILEGE;
	entry.code.present = 1;
	entry.code.limit16 = static_cast<uint8_t>(limit >> 16);
	entry.code.opsz = DESC_CODE_32B;
	entry.code.granular = granular;
	entry.code.base24 = static_cast<uint8_t>(base >> 24);
	return entry;
}

constexpr int createSelector(int entryNumber) { return (entryNumber << 3) | 0x4 /* TI=1 */ | USER_PRIVILEGE; }

inline void writeTsdSlot(uint32_t slot, uint64_t val) {
	// mov qword ptr gs:[slot*8], val
	*(volatile uint64_t __seg_gs *)(slot * sizeof(void *)) = val;
}

} // namespace

int tebThreadSetup(int entryNumber, TEB *teb) {
	bool alloc = entryNumber == -1;
	if (alloc) {
		ldt_entry unused{};
		entryNumber = i386_get_ldt(0, &unused, 1);
		if (entryNumber < 0) {
			return entryNumber;
		}
		DEBUG_LOG("Allocating LDT entry %d\n", entryNumber);
		// Create code LDT entry at entry_number + 1
		ldt_entry codeLdt = createLdtEntry(0, 0xFFFFFFFF, true);
		int codeLdtEntry = entryNumber++;
		int ret = i386_set_ldt(codeLdtEntry, &codeLdt, 1);
		if (ret < 0) {
			return ret;
		} else if (ret != codeLdtEntry) {
			errno = EALREADY;
			return -EALREADY;
		}
		DEBUG_LOG("Code selector %x\n", createSelector(ret));
		// Create data LDT entry at entry_number + 2
		ldt_entry dataLdt = createLdtEntry(0, 0xFFFFFFFF, false);
		int dataLdtEntry = entryNumber++;
		ret = i386_set_ldt(dataLdtEntry, &dataLdt, 1);
		if (ret < 0) {
			return ret;
		} else if (ret != dataLdtEntry) {
			errno = EALREADY;
			return -EALREADY;
		}
		DEBUG_LOG("Data selector %x\n", createSelector(dataLdtEntry));
	}
	uintptr_t tebBase = reinterpret_cast<uintptr_t>(teb);
	if (tebBase > 0xFFFFFFFF) {
		DEBUG_LOG("TEB base address exceeds 32-bit limit\n");
		errno = EINVAL;
		return -EINVAL;
	}
	// Store the TEB base address in the reserved slot for Windows 64-bit (gs:[0x30])
	writeTsdSlot(_PTHREAD_TSD_SLOT_RESERVED_WIN64, static_cast<uint32_t>(tebBase));
	// Rosetta 2 requires size 0x1000 (limit 0xFFF) specifically
	ldt_entry fsLdt = createLdtEntry(static_cast<uint32_t>(tebBase), 0x1000, false);
	int ret = i386_set_ldt(entryNumber, &fsLdt, 1);
	if (ret < 0) {
		return ret;
	} else if (ret != entryNumber) {
		errno = EALREADY;
		return -EALREADY;
	}
	teb->CurrentFsSelector = createSelector(entryNumber);
	return entryNumber;
}
