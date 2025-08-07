#include "common.h"

namespace advapi32 {
	unsigned int WIN_FUNC RegOpenKeyExA(void *hKey, const char *lpSubKey, unsigned int ulOptions, void *samDesired, void **phkResult) {
		DEBUG_LOG("RegOpenKeyExA(key=%p, subkey=%s, ...)\n", hKey, lpSubKey);
		return 1; // screw them for now
	}

	bool WIN_FUNC CryptAcquireContextW(void** phProv, const wchar_t* pszContainer, const wchar_t* pszProvider, unsigned int dwProvType, unsigned int dwFlags){
		DEBUG_LOG("STUB: CryptAcquireContextW(%p)\n", phProv);

		// to quote the guy above me: screw them for now
		static int lmao = 42;
		if (phProv) {
			*phProv = &lmao;
			return true;
		}

		return false;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "RegOpenKeyExA") == 0) return (void *) advapi32::RegOpenKeyExA;
	if (strcmp(name, "CryptAcquireContextW") == 0) return (void*) advapi32::CryptAcquireContextW;
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
