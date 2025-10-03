#pragma once

#include "common.h"

#include <cstdint>

namespace wibo::access {

// Maps the Win32 generic access bits (GENERIC_* constants) to the
// object-specific rights supplied in the mapping table.
struct GenericMapping {
	uint32_t genericRead;
	uint32_t genericWrite;
	uint32_t genericExecute;
	uint32_t genericAll;
};

struct NormalizedAccess {
	uint32_t requestedMask; // mask after generic expansion + implicit bits
	uint32_t grantedMask;	// requested & supported
	uint32_t deniedMask;	// requested & ~supported
};

uint32_t mapGenericMask(uint32_t desiredMask, const GenericMapping &mapping);
NormalizedAccess normalizeDesiredAccess(uint32_t desiredMask, const GenericMapping &mapping, uint32_t supportedMask,
										uint32_t alwaysGrantMask = 0, uint32_t defaultMask = 0);

inline bool containsAny(uint32_t mask, uint32_t rights) { return (mask & rights) != 0; }
inline bool containsAll(uint32_t mask, uint32_t rights) { return (mask & rights) == rights; }

extern const GenericMapping kFileGenericMapping;
extern const GenericMapping kDirectoryGenericMapping;

constexpr DWORD kFileSpecificRightsMask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE |
										  FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
constexpr DWORD kDirectorySpecificRightsMask = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
											   FILE_TRAVERSE | FILE_DELETE_CHILD | FILE_READ_EA | FILE_WRITE_EA |
											   FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;

} // namespace wibo::access
