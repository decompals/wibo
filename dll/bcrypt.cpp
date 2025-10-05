#include "common.h"
#include "context.h"
#include "errors.h"
#include "modules.h"

#include <sys/random.h>
#include <vector>

namespace {

typedef PVOID BCRYPT_ALG_HANDLE;

constexpr ULONG BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 0x00000001;
constexpr ULONG BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

bool fillWithSystemRandom(PUCHAR buffer, size_t length) {
	while (length > 0) {
		ssize_t written = getrandom(buffer, length, 0);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (written == 0)
			continue;
		buffer += written;
		length -= static_cast<size_t>(written);
	}
	return true;
}

} // namespace

namespace bcrypt {

NTSTATUS WIN_FUNC BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("BCryptGenRandom(%p, %p, %lu, %lu)\n", hAlgorithm, pbBuffer, cbBuffer, dwFlags);
	if (pbBuffer == nullptr && cbBuffer != 0)
		return STATUS_INVALID_HANDLE;

	if (hAlgorithm != nullptr)
		return STATUS_NOT_IMPLEMENTED;

	if ((dwFlags & BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
		return STATUS_INVALID_HANDLE;

	ULONG allowedFlags = BCRYPT_RNG_USE_ENTROPY_IN_BUFFER | BCRYPT_USE_SYSTEM_PREFERRED_RNG;
	if ((dwFlags & ~allowedFlags) != 0)
		return STATUS_INVALID_PARAMETER;

	if (cbBuffer == 0)
		return STATUS_SUCCESS;

	std::vector<unsigned char> entropy;
	if ((dwFlags & BCRYPT_RNG_USE_ENTROPY_IN_BUFFER) && pbBuffer != nullptr)
		entropy.assign(pbBuffer, pbBuffer + cbBuffer);

	if (!fillWithSystemRandom(pbBuffer, cbBuffer))
		return STATUS_UNEXPECTED_IO_ERROR;

	if (!entropy.empty()) {
		for (size_t i = 0; i < entropy.size(); ++i)
			pbBuffer[i] ^= entropy[i];
	}
	return STATUS_SUCCESS;
}

} // namespace bcrypt

static void *resolveByName(const char *name) {
	if (strcmp(name, "BCryptGenRandom") == 0)
		return (void *)bcrypt::BCryptGenRandom;
	return nullptr;
}

wibo::ModuleStub lib_bcrypt = {
	(const char *[]){
		"bcrypt",
		nullptr,
	},
	resolveByName,
	nullptr,
};
