#include "common.h"

namespace version {
	unsigned int WIN_FUNC GetFileVersionInfoSizeA(const char* lptstrFilename, unsigned int* outZero) {
		DEBUG_LOG("GetFileVersionInfoSizeA %s\n", lptstrFilename);
		*outZero = 0;
		// stub: signal an error
		wibo::lastError = 0;
		return 0;
	}
}

void *wibo::resolveVersion(const char *name) {
	if (strcmp(name, "GetFileVersionInfoSizeA") == 0) return (void *) version::GetFileVersionInfoSizeA;
	return 0;
}
