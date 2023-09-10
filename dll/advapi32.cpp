#include "common.h"

namespace advapi32 {
	unsigned int WIN_FUNC RegOpenKeyExA(void *hKey, const char *lpSubKey, unsigned int ulOptions, void *samDesired, void **phkResult) {
		DEBUG_LOG("RegOpenKeyExA(key=%p, subkey=%s, ...)\n", hKey, lpSubKey);
		return 1; // screw them for now
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "RegOpenKeyExA") == 0) return (void *) advapi32::RegOpenKeyExA;
	return nullptr;
}

wibo::Module lib_advapi32 = {
	(const char *[]){
		"advapi32",
		"advapi32.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
