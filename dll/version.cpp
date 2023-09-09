#include "common.h"

namespace version {
	unsigned int WIN_FUNC GetFileVersionInfoSizeA(const char* lptstrFilename, unsigned int* outZero) {
		DEBUG_LOG("GetFileVersionInfoSizeA %s\n", lptstrFilename);
		*outZero = 0;
		wibo::lastError = 0;
		return 0;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "GetFileVersionInfoSizeA") == 0) return (void *) version::GetFileVersionInfoSizeA;
	return nullptr;
}

wibo::Module lib_version = {
	(const char *[]){
		"version",
		"version.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
