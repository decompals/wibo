#include "common.h"
#include <sys/random.h>

namespace advapi32 {
	unsigned int WIN_FUNC RegOpenKeyExA(void *hKey, const char *lpSubKey, unsigned int ulOptions, void *samDesired, void **phkResult) {
		DEBUG_LOG("RegOpenKeyExA(key=%p, subkey=%s, ...)\n", hKey, lpSubKey);
		return 1; // screw them for now
	}

	bool WIN_FUNC CryptReleaseContext(void* hProv, unsigned int dwFlags) {
		DEBUG_LOG("STUB: CryptReleaseContext %p %u\n", hProv, dwFlags);
		return true;
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

	bool WIN_FUNC CryptGenRandom(void* hProv, unsigned int dwLen, char* pbBuffer){
		DEBUG_LOG("STUB: CryptGenRandom(%p)\n", hProv);
		if (!pbBuffer || dwLen == 0) return false;

		ssize_t ret = getrandom(pbBuffer, dwLen, 0);
		if (ret < 0 || (size_t)ret != dwLen) {
			return false;
		}

		return true;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "RegOpenKeyExA") == 0) return (void *) advapi32::RegOpenKeyExA;
	if (strcmp(name, "CryptReleaseContext") == 0) return (void*) advapi32::CryptReleaseContext;
	if (strcmp(name, "CryptAcquireContextW") == 0) return (void*) advapi32::CryptAcquireContextW;
	if (strcmp(name, "CryptGenRandom") == 0) return (void*) advapi32::CryptGenRandom;
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
