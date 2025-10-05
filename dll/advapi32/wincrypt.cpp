#include "wincrypt.h"

#include "common.h"
#include "context.h"
#include "errors.h"

#include <cstring>
#include <sys/random.h>
#include <vector>

namespace {

struct HashObject {
	ALG_ID algid = 0;
	std::vector<uint8_t> data;
	std::vector<uint8_t> digest;
	bool digestComputed = false;
};

uint32_t leftRotate(uint32_t value, uint32_t bits) { return (value << bits) | (value >> (32 - bits)); }

std::vector<uint8_t> computeMD5(const std::vector<uint8_t> &input) {
	static const uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
								   5, 9,  14, 20, 5, 9,	 14, 20, 5, 9,	14, 20, 5, 9,  14, 20,
								   4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
								   6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
	static const uint32_t K[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

	std::vector<uint8_t> data = input;
	uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8ULL;
	data.push_back(0x80);
	while ((data.size() % 64) != 56) {
		data.push_back(0);
	}
	for (int i = 0; i < 8; ++i) {
		data.push_back(static_cast<uint8_t>((bitLen >> (8 * i)) & 0xFF));
	}

	uint32_t A = 0x67452301;
	uint32_t B = 0xEFCDAB89;
	uint32_t C = 0x98BADCFE;
	uint32_t D = 0x10325476;

	for (size_t offset = 0; offset < data.size(); offset += 64) {
		uint32_t M[16];
		for (int i = 0; i < 16; ++i) {
			M[i] = static_cast<uint32_t>(data[offset + i * 4]) |
				   (static_cast<uint32_t>(data[offset + i * 4 + 1]) << 8) |
				   (static_cast<uint32_t>(data[offset + i * 4 + 2]) << 16) |
				   (static_cast<uint32_t>(data[offset + i * 4 + 3]) << 24);
		}
		uint32_t a = A;
		uint32_t b = B;
		uint32_t c = C;
		uint32_t d = D;
		for (int i = 0; i < 64; ++i) {
			uint32_t F;
			int g;
			if (i < 16) {
				F = (b & c) | ((~b) & d);
				g = i;
			} else if (i < 32) {
				F = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				F = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			} else {
				F = c ^ (b | (~d));
				g = (7 * i) % 16;
			}
			uint32_t temp = d;
			d = c;
			c = b;
			uint32_t rotateVal = a + F + K[i] + M[g];
			b = b + leftRotate(rotateVal, s[i]);
			a = temp;
		}
		A += a;
		B += b;
		C += c;
		D += d;
	}

	std::vector<uint8_t> digest(16);
	uint32_t output[4] = {A, B, C, D};
	for (int i = 0; i < 4; ++i) {
		digest[i * 4] = static_cast<uint8_t>(output[i] & 0xFF);
		digest[i * 4 + 1] = static_cast<uint8_t>((output[i] >> 8) & 0xFF);
		digest[i * 4 + 2] = static_cast<uint8_t>((output[i] >> 16) & 0xFF);
		digest[i * 4 + 3] = static_cast<uint8_t>((output[i] >> 24) & 0xFF);
	}
	return digest;
}

std::vector<uint8_t> computeSHA1(const std::vector<uint8_t> &input) {
	std::vector<uint8_t> data = input;
	uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8ULL;
	data.push_back(0x80);
	while ((data.size() % 64) != 56) {
		data.push_back(0);
	}
	for (int i = 7; i >= 0; --i) {
		data.push_back(static_cast<uint8_t>((bitLen >> (8 * i)) & 0xFF));
	}

	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	for (size_t offset = 0; offset < data.size(); offset += 64) {
		uint32_t w[80];
		for (int i = 0; i < 16; ++i) {
			w[i] = (static_cast<uint32_t>(data[offset + i * 4]) << 24) |
				   (static_cast<uint32_t>(data[offset + i * 4 + 1]) << 16) |
				   (static_cast<uint32_t>(data[offset + i * 4 + 2]) << 8) |
				   static_cast<uint32_t>(data[offset + i * 4 + 3]);
		}
		for (int i = 16; i < 80; ++i) {
			w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		}
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		for (int i = 0; i < 80; ++i) {
			uint32_t f;
			uint32_t k;
			if (i < 20) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			} else if (i < 40) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			} else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			} else {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}
			uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = leftRotate(b, 30);
			b = a;
			a = temp;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	std::vector<uint8_t> digest(20);
	uint32_t output[5] = {h0, h1, h2, h3, h4};
	for (int i = 0; i < 5; ++i) {
		digest[i * 4] = static_cast<uint8_t>((output[i] >> 24) & 0xFF);
		digest[i * 4 + 1] = static_cast<uint8_t>((output[i] >> 16) & 0xFF);
		digest[i * 4 + 2] = static_cast<uint8_t>((output[i] >> 8) & 0xFF);
		digest[i * 4 + 3] = static_cast<uint8_t>(output[i] & 0xFF);
	}
	return digest;
}

bool computeDigest(HashObject &hash) {
	if (hash.digestComputed) {
		return true;
	}
	switch (hash.algid) {
	case CALG_MD5:
		hash.digest = computeMD5(hash.data);
		hash.digestComputed = true;
		return true;
	case CALG_SHA1:
		hash.digest = computeSHA1(hash.data);
		hash.digestComputed = true;
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

} // namespace

namespace advapi32 {

BOOL WIN_FUNC CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CryptReleaseContext(%p, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)), dwFlags);
	(void)hProv;
	(void)dwFlags;
	wibo::lastError = ERROR_SUCCESS;
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
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*phProv = static_cast<HCRYPTPROV>(reinterpret_cast<uintptr_t>(&dummyProvider));
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptGenRandom(%p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)));
	(void)hProv;
	if (!pbBuffer || dwLen == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	ssize_t ret = getrandom(pbBuffer, dwLen, 0);
	if (ret < 0 || static_cast<DWORD>(ret) != dwLen) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}

	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptCreateHash(%p, %u, %p, %u, %p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hProv)), Algid,
			  reinterpret_cast<void *>(static_cast<uintptr_t>(hKey)), dwFlags, phHash);
	(void)hProv;
	if (!phHash) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (dwFlags != 0) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}
	if (hKey != 0) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}
	if (Algid != CALG_MD5 && Algid != CALG_SHA1) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}
	auto *hash = new HashObject;
	hash->algid = Algid;
	hash->digestComputed = false;
	hash->data.clear();
	hash->digest.clear();
	*phHash = hashHandleFromObject(hash);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptHashData(%p, %p, %u, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)), pbData,
			  dwDataLen, dwFlags);
	if (dwFlags != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash || (dwDataLen != 0 && !pbData)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (pbData && dwDataLen) {
		hash->data.insert(hash->data.end(), pbData, pbData + dwDataLen);
		hash->digestComputed = false;
		hash->digest.clear();
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptGetHashParam(%p, %u, %p, %p, %u)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)),
			  dwParam, pbData, pdwDataLen, dwFlags);
	if (dwFlags != 0 || !pdwDataLen) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	switch (dwParam) {
	case HP_ALGID: {
		DWORD required = sizeof(ALG_ID);
		if (!pbData) {
			*pdwDataLen = required;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (*pdwDataLen < required) {
			*pdwDataLen = required;
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		memcpy(pbData, &hash->algid, required);
		*pdwDataLen = required;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	case HP_HASHSIZE: {
		DWORD size = 0;
		switch (hash->algid) {
		case CALG_MD5:
			size = 16;
			break;
		case CALG_SHA1:
			size = 20;
			break;
		default:
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return FALSE;
		}
		if (!pbData) {
			*pdwDataLen = sizeof(DWORD);
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (*pdwDataLen < sizeof(DWORD)) {
			*pdwDataLen = sizeof(DWORD);
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		memcpy(pbData, &size, sizeof(DWORD));
		*pdwDataLen = sizeof(DWORD);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	case HP_HASHVAL: {
		if (!computeDigest(*hash)) {
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return FALSE;
		}
		DWORD required = static_cast<DWORD>(hash->digest.size());
		if (!pbData) {
			*pdwDataLen = required;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (*pdwDataLen < required) {
			*pdwDataLen = required;
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		memcpy(pbData, hash->digest.data(), required);
		*pdwDataLen = required;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	default:
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}
}

BOOL WIN_FUNC CryptDestroyHash(HCRYPTHASH hHash) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CryptDestroyHash(%p)\n", reinterpret_cast<void *>(static_cast<uintptr_t>(hHash)));
	auto *hash = hashObjectFromHandle(hHash);
	if (!hash) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	delete hash;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace advapi32
