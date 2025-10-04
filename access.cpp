#include "access.h"

namespace wibo::access {

const GenericMapping kFileGenericMapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};

const GenericMapping kDirectoryGenericMapping{
	STANDARD_RIGHTS_READ | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_TRAVERSE | SYNCHRONIZE,
	STANDARD_RIGHTS_WRITE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | SYNCHRONIZE,
	STANDARD_RIGHTS_EXECUTE | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
	FILE_ALL_ACCESS | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | FILE_DELETE_CHILD};

uint32_t mapGenericMask(uint32_t desiredMask, const GenericMapping &mapping) {
	uint32_t mask = desiredMask;
	if ((mask & GENERIC_ALL) != 0) {
		mask = (mask & ~GENERIC_ALL) | mapping.genericAll;
	}
	if ((mask & GENERIC_READ) != 0) {
		mask = (mask & ~GENERIC_READ) | mapping.genericRead;
	}
	if ((mask & GENERIC_WRITE) != 0) {
		mask = (mask & ~GENERIC_WRITE) | mapping.genericWrite;
	}
	if ((mask & GENERIC_EXECUTE) != 0) {
		mask = (mask & ~GENERIC_EXECUTE) | mapping.genericExecute;
	}
	return mask;
}

NormalizedAccess normalizeDesiredAccess(uint32_t desiredMask, const GenericMapping &mapping, uint32_t supportedMask,
										uint32_t alwaysGrantMask, uint32_t defaultMask) {
	NormalizedAccess out{};
	uint32_t requested = mapGenericMask(desiredMask, mapping);
	if (requested == 0 && desiredMask == 0 && defaultMask != 0) {
		requested = defaultMask;
	}
	requested |= alwaysGrantMask;

	out.requestedMask = requested;
	out.grantedMask = requested & supportedMask;
	out.deniedMask = requested & ~supportedMask;
	return out;
}

} // namespace wibo::access
