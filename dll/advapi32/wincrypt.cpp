#include "wincrypt.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "kernel32/internal.h"

#include "md5.h"
#define SHA1_IMPLEMENTATION
#include "sha1.h"

#include <cstring>
#include <sys/random.h>

namespace {

struct HashObject {
	ALG_ID algid = 0;
	unsigned char digest[20]{};
	union {
		MD5_CTX md5{};
		sha1_context sha1;
	};
};

bool computeDigest(HashObject &hash) {
	switch (hash.algid) {
	case CALG_MD5:
		MD5_Final(hash.digest, &hash.md5);
		return true;
	case CALG_SHA1:
		sha1_finalize(&hash.sha1, hash.digest);
		return true;
	default:
		return false;
	}
}

HashObject *hashObjectFromHandle(HCRYPTHASH hHash) {
	if (hHash == 0) {
		return nullptr;
	}
	return reinterpret_cast<HashObject *>(static_cast<uintptr_t>(hHash));
}

HCRYPTHASH hashHandleFromObject(HashObject *hash) { return static_cast<HCRYPTHASH>(reinterpret_cast<uintptr_t>(hash)); }

DWORD hashSizeForAlgid(ALG_ID algid) {
	switch (algid) {
	case CALG_MD5:
		return 16;
	case CALG_SHA1:
		return 20;
	default:
		return 0;
	}
}

} // namespace

namespace advapi32 {

BOOL WIN_FUNC CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CryptReleaseContext(%p, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)), dwFlags);
	(void)hProv;
	(void)dwFlags;
	return TRUE;
}

BOOL WIN_FUNC CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType,
								   DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CryptAcquireContextW(%p, %p, %p, %u, %u)\n", phProv, pszContainer, pszProvider, dwProvType,
			  dwFlags);
	// to quote the guy above me: screw them for now
	static int dummyProvider = 42;
	if (!phProv) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*phProv = static_cast<HCRYPTPROV>(reinterpret_cast<uintptr_t>(&dummyProvider));
	return TRUE;
}

BOOL WIN_FUNC CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptGenRandom(%p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)));
	(void)hProv;
	if (!pbBuffer || dwLen == 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	ssize_t ret = getrandom(pbBuffer, dwLen, 0);
	if (ret < 0 || static_cast<DWORD>(ret) != dwLen) {
		kernel32::setLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

	return TRUE;
}

BOOL WIN_FUNC CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptCreateHash(%p, %u, %p, %u, %p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)), Algid,
			  reinterpret_cast<void *>(static_cast<uintptr_t>(hKey)), dwFlags, phHash);
	(void)hProv;
	if (!phHash) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwFlags != 0) {
		kernel32::setLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
	if (hKey != 0) {
		kernel32::setLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
	if (Algid != CALG_MD5 && Algid != CALG_SHA1) {
		kernel32::setLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
	auto *hash = new HashObject;
	hash->algid = Algid;
	if (Algid == CALG_MD5) {
		MD5_Init(&hash->md5);
	} else if (Algid == CALG_SHA1) {
		sha1_init(&hash->sha1);
	}
	*phHash = hashHandleFromObject(hash);
	return TRUE;
}

BOOL WIN_FUNC CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptHashData(%p, %p, %u, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)), pbData,
			  dwDataLen, dwFlags);
	if (dwFlags != 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash || (dwDataLen != 0 && !pbData)) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (pbData && dwDataLen) {
		if (hash->algid == CALG_MD5) {
			MD5_Update(&hash->md5, pbData, dwDataLen);
		} else if (hash->algid == CALG_SHA1) {
			sha1_update(&hash->sha1, pbData, dwDataLen);
		}
	}
	return TRUE;
}

BOOL WIN_FUNC CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptGetHashParam(%p, %u, %p, %p, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)),
			  dwParam, pbData, pdwDataLen, dwFlags);
	if (dwFlags != 0 || !pdwDataLen) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	switch (dwParam) {
	case HP_ALGID: {
		DWORD required = sizeof(ALG_ID);
		if (!pbData) {
			*pdwDataLen = required;
			return TRUE;
		}
		if (*pdwDataLen < required) {
			*pdwDataLen = required;
			kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
		memcpy(pbData, &hash->algid, required);
		*pdwDataLen = required;
		return TRUE;
	}
	case HP_HASHSIZE: {
		DWORD required = sizeof(DWORD);
		if (!pbData) {
			*pdwDataLen = required;
			return TRUE;
		}
		if (*pdwDataLen < required) {
			*pdwDataLen = required;
			kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
		DWORD size = hashSizeForAlgid(hash->algid);
		if (size == 0) {
			kernel32::setLastError(ERROR_NOT_SUPPORTED);
			return FALSE;
		}
		memcpy(pbData, &size, required);
		*pdwDataLen = required;
		return TRUE;
	}
	case HP_HASHVAL: {
		if (!computeDigest(*hash)) {
			kernel32::setLastError(ERROR_NOT_SUPPORTED);
			return FALSE;
		}
		DWORD size = hashSizeForAlgid(hash->algid);
		if (size == 0) {
			kernel32::setLastError(ERROR_NOT_SUPPORTED);
			return FALSE;
		}
		if (!pbData) {
			*pdwDataLen = size;
			return TRUE;
		}
		if (*pdwDataLen < size) {
			*pdwDataLen = size;
			kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
		memcpy(pbData, hash->digest, size);
		*pdwDataLen = size;
		return TRUE;
	}
	default:
		kernel32::setLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
}

BOOL WIN_FUNC CryptDestroyHash(HCRYPTHASH hHash) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptDestroyHash(%p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)));
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	delete hash;
	return TRUE;
}

} // namespace advapi32
