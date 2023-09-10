#include "common.h"

#include <algorithm>
#include <climits>
#include <random>

typedef PVOID BCRYPT_ALG_HANDLE;

namespace bcrypt {

using random_bytes_engine = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char>;

NTSTATUS WIN_FUNC BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
	DEBUG_LOG("BCryptGenRandom(%p, %p, %lu, %lu)\n", hAlgorithm, pbBuffer, cbBuffer, dwFlags);
	assert(hAlgorithm == nullptr);
	assert(dwFlags == 0 || dwFlags == 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */);
	random_bytes_engine rbe;
	std::generate(pbBuffer, pbBuffer + cbBuffer, std::ref(rbe));
	return STATUS_SUCCESS;
}

} // namespace bcrypt

static void *resolveByName(const char *name) {
	if (strcmp(name, "BCryptGenRandom") == 0)
		return (void *)bcrypt::BCryptGenRandom;
	return nullptr;
}

wibo::Module lib_bcrypt = {
	(const char *[]){
		"bcrypt",
		"bcrypt.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
