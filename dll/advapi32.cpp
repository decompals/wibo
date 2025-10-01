#include "common.h"
#include "errors.h"
#include "handles.h"
#include "strutil.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/random.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace {
	constexpr DWORD REG_OPTION_OPEN_LINK = 0x00000008;
	constexpr DWORD KEY_WOW64_64KEY = 0x00000100;
	constexpr DWORD KEY_WOW64_32KEY = 0x00000200;

	struct RegistryKeyHandleData {
		std::u16string canonicalPath;
		bool predefined = false;
	};

	struct PredefinedKeyInfo {
		uintptr_t value;
		const char16_t *name;
	};

	static constexpr PredefinedKeyInfo predefinedKeyInfos[] = {
		{0x80000000u, u"HKEY_CLASSES_ROOT"},
		{0x80000001u, u"HKEY_CURRENT_USER"},
		{0x80000002u, u"HKEY_LOCAL_MACHINE"},
		{0x80000003u, u"HKEY_USERS"},
		{0x80000004u, u"HKEY_PERFORMANCE_DATA"},
		{0x80000005u, u"HKEY_CURRENT_CONFIG"},
	};

	static constexpr size_t predefinedKeyCount = sizeof(predefinedKeyInfos) / sizeof(predefinedKeyInfos[0]);

	static std::mutex registryMutex;
	static bool predefinedHandlesInitialized = false;
	static RegistryKeyHandleData predefinedHandles[predefinedKeyCount];
	static bool registryInitialized = false;
	static std::unordered_set<std::u16string> existingKeys;
	struct Luid;
	static std::mutex privilegeMapMutex;
	static std::unordered_map<std::string, Luid> privilegeLuidCache;

	static std::u16string canonicalizeKeySegment(const std::u16string &input) {
		std::u16string result;
		result.reserve(input.size());
		bool lastWasSlash = false;
		for (char16_t ch : input) {
			char16_t normalized = (ch == u'/') ? u'\\' : ch;
			if (normalized == u'\\') {
				if (!result.empty() && !lastWasSlash) {
					result.push_back(u'\\');
				}
				lastWasSlash = true;
				continue;
			}
			lastWasSlash = false;
			uint16_t lowered = wcharToLower(static_cast<uint16_t>(normalized));
			result.push_back(static_cast<char16_t>(lowered));
		}
		while (!result.empty() && result.back() == u'\\') {
			result.pop_back();
		}
		auto it = result.begin();
		while (it != result.end() && *it == u'\\') {
			it = result.erase(it);
		}
		return result;
	}

	static std::u16string canonicalizeKeySegment(const uint16_t *input) {
		if (!input) {
			return {};
		}
		std::u16string wide(reinterpret_cast<const char16_t *>(input), wstrlen(input));
		return canonicalizeKeySegment(wide);
	}

	static void initializePredefinedHandlesLocked() {
		if (predefinedHandlesInitialized) {
			return;
		}
		for (size_t i = 0; i < predefinedKeyCount; ++i) {
			predefinedHandles[i].canonicalPath = canonicalizeKeySegment(std::u16string(predefinedKeyInfos[i].name));
			predefinedHandles[i].predefined = true;
		}
		predefinedHandlesInitialized = true;
	}

	static RegistryKeyHandleData *predefinedHandleForValue(uintptr_t value) {
		for (size_t i = 0; i < predefinedKeyCount; ++i) {
			if (predefinedKeyInfos[i].value == value) {
				return &predefinedHandles[i];
			}
		}
		return nullptr;
	}

	static RegistryKeyHandleData *handleDataFromHKeyLocked(HKEY hKey) {
		uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
		if (raw == 0) {
			return nullptr;
		}
		initializePredefinedHandlesLocked();
		if (auto *predefined = predefinedHandleForValue(raw)) {
			return predefined;
		}
		auto data = handles::dataFromHandle(hKey, false);
		if (data.type != handles::TYPE_REGISTRY_KEY || data.ptr == nullptr) {
			return nullptr;
		}
		return static_cast<RegistryKeyHandleData *>(data.ptr);
	}

	static bool isPredefinedKeyHandle(HKEY hKey) {
		uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
		for (size_t i = 0; i < predefinedKeyCount; ++i) {
			if (predefinedKeyInfos[i].value == raw) {
				return true;
			}
		}
		return false;
	}

	static void ensureRegistryInitializedLocked() {
		if (registryInitialized) {
			return;
		}
		initializePredefinedHandlesLocked();
		for (size_t i = 0; i < predefinedKeyCount; ++i) {
			existingKeys.insert(predefinedHandles[i].canonicalPath);
		}
		registryInitialized = true;
	}

	using ALG_ID = unsigned int;

	constexpr ALG_ID CALG_MD5 = 0x00008003;
	constexpr ALG_ID CALG_SHA1 = 0x00008004;

	constexpr DWORD HP_ALGID = 0x00000001;
	constexpr DWORD HP_HASHVAL = 0x00000002;
	constexpr DWORD HP_HASHSIZE = 0x00000004;

	constexpr DWORD SECURITY_DESCRIPTOR_REVISION = 1;
	constexpr uint16_t SE_DACL_PRESENT = 0x0004;
	constexpr uint16_t SE_DACL_DEFAULTED = 0x0008;

	struct SecurityDescriptor {
		uint8_t Revision = 0;
		uint8_t Sbz1 = 0;
		uint16_t Control = 0;
		void *Owner = nullptr;
		void *Group = nullptr;
		void *Sacl = nullptr;
		void *Dacl = nullptr;
	};

	struct HashObject {
		ALG_ID algid = 0;
		std::vector<uint8_t> data;
		std::vector<uint8_t> digest;
		bool digestComputed = false;
	};

	struct TokenObject {
		HANDLE processHandle = nullptr;
		DWORD desiredAccess = 0;
	};

	struct SidIdentifierAuthority {
		uint8_t Value[6] = {0};
	};

	struct Sid {
		uint8_t Revision = 1;
		uint8_t SubAuthorityCount = 0;
		SidIdentifierAuthority IdentifierAuthority = {};
		uint32_t SubAuthority[1] = {0};
	};

	struct SidAndAttributes {
		Sid *SidPtr = nullptr;
		DWORD Attributes = 0;
	};

	struct TokenUserData {
		SidAndAttributes User;
	};

	enum SID_NAME_USE {
		SidTypeUser = 1,
		SidTypeGroup,
		SidTypeDomain,
		SidTypeAlias,
		SidTypeWellKnownGroup,
		SidTypeDeletedAccount,
		SidTypeInvalid,
		SidTypeUnknown,
		SidTypeComputer,
		SidTypeLabel
	};

	bool isLocalSystemSid(const Sid *sid) {
		if (!sid) {
			return false;
		}
		static const uint8_t ntAuthority[6] = {0, 0, 0, 0, 0, 5};
		if (sid->Revision != 1 || sid->SubAuthorityCount != 1) {
			return false;
		}
		for (size_t i = 0; i < 6; ++i) {
			if (sid->IdentifierAuthority.Value[i] != ntAuthority[i]) {
				return false;
			}
		}
		return sid->SubAuthority[0] == 18; // SECURITY_LOCAL_SYSTEM_RID
	}

	struct Luid {
		uint32_t LowPart = 0;
		int32_t HighPart = 0;
	};

	struct LuidAndAttributes {
		Luid value;
		DWORD Attributes = 0;
	};

	struct TokenStatisticsData {
		Luid tokenId;
		Luid authenticationId;
		int64_t expirationTime = 0;
		uint32_t tokenType = 0;
		uint32_t impersonationLevel = 0;
		uint32_t dynamicCharged = 0;
		uint32_t dynamicAvailable = 0;
		uint32_t groupCount = 0;
		uint32_t privilegeCount = 0;
		Luid modifiedId;
	};

	static inline uint32_t leftRotate(uint32_t value, uint32_t bits) {
		return (value << bits) | (value >> (32 - bits));
	}

	static std::vector<uint8_t> computeMD5(const std::vector<uint8_t> &input) {
		static const uint32_t s[64] = {
			7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
			4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
		};
		static const uint32_t K[64] = {
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
		};

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

	static std::vector<uint8_t> computeSHA1(const std::vector<uint8_t> &input) {
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

	static bool computeDigest(HashObject &hash) {
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
}

namespace advapi32 {
	LSTATUS WIN_FUNC RegOpenKeyExW(HKEY hKey, const uint16_t *lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
		std::string subKeyString = lpSubKey ? wideStringToString(lpSubKey) : std::string("(null)");
		DEBUG_LOG("RegOpenKeyExW(%p, %s, %u, 0x%x, %p)\n", hKey, subKeyString.c_str(), ulOptions, samDesired, phkResult);
		if (!phkResult) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return ERROR_INVALID_PARAMETER;
		}
		*phkResult = nullptr;
		if ((ulOptions & ~REG_OPTION_OPEN_LINK) != 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return ERROR_INVALID_PARAMETER;
		}
		if (ulOptions & REG_OPTION_OPEN_LINK) {
			DEBUG_LOG("RegOpenKeyExW: ignoring REG_OPTION_OPEN_LINK\n");
		}
		REGSAM sanitizedAccess = samDesired & ~(KEY_WOW64_64KEY | KEY_WOW64_32KEY);
		if (sanitizedAccess != samDesired) {
			DEBUG_LOG("RegOpenKeyExW: ignoring WOW64 access mask 0x%x\n", samDesired ^ sanitizedAccess);
		}
		(void) sanitizedAccess;
		std::lock_guard<std::mutex> lock(registryMutex);
		ensureRegistryInitializedLocked();
		RegistryKeyHandleData *baseHandle = handleDataFromHKeyLocked(hKey);
		if (!baseHandle) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return ERROR_INVALID_HANDLE;
		}
		std::u16string targetPath = baseHandle->canonicalPath;
		if (lpSubKey && lpSubKey[0] != 0) {
			std::u16string subComponent = canonicalizeKeySegment(lpSubKey);
			if (!subComponent.empty()) {
				if (!targetPath.empty()) {
					targetPath.push_back(u'\\');
				}
				targetPath.append(subComponent);
			}
		}
		if (targetPath.empty()) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return ERROR_INVALID_HANDLE;
		}
		if (existingKeys.find(targetPath) == existingKeys.end()) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return ERROR_FILE_NOT_FOUND;
		}
		if (!lpSubKey || lpSubKey[0] == 0) {
			if (baseHandle->predefined) {
				*phkResult = hKey;
				wibo::lastError = ERROR_SUCCESS;
				return ERROR_SUCCESS;
			}
		}
		auto *handleData = new RegistryKeyHandleData;
		handleData->canonicalPath = targetPath;
		handleData->predefined = false;
		auto handle = handles::allocDataHandle({handles::TYPE_REGISTRY_KEY, handleData, sizeof(*handleData)});
		*phkResult = reinterpret_cast<HKEY>(handle);
		wibo::lastError = ERROR_SUCCESS;
		return ERROR_SUCCESS;
	}

	LSTATUS WIN_FUNC RegOpenKeyExA(HKEY hKey, const char *lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
		DEBUG_LOG("RegOpenKeyExA(%p, %s, %u, 0x%x, %p)\n", hKey, lpSubKey ? lpSubKey : "(null)", ulOptions, samDesired, phkResult);
		const uint16_t *widePtr = nullptr;
		std::vector<uint16_t> wideStorage;
		if (lpSubKey) {
			wideStorage = stringToWideString(lpSubKey);
			widePtr = wideStorage.data();
		}
		return RegOpenKeyExW(hKey, widePtr, ulOptions, samDesired, phkResult);
	}

	LSTATUS WIN_FUNC RegCloseKey(HKEY hKey) {
		DEBUG_LOG("RegCloseKey(%p)\n", hKey);
		if (isPredefinedKeyHandle(hKey)) {
			wibo::lastError = ERROR_SUCCESS;
			return ERROR_SUCCESS;
		}
		auto data = handles::dataFromHandle(hKey, true);
		if (data.type != handles::TYPE_REGISTRY_KEY || data.ptr == nullptr) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return ERROR_INVALID_HANDLE;
		}
		auto *handleData = static_cast<RegistryKeyHandleData *>(data.ptr);
		delete handleData;
		wibo::lastError = ERROR_SUCCESS;
		return ERROR_SUCCESS;
	}

	BOOL WIN_FUNC CryptReleaseContext(void* hProv, unsigned int dwFlags) {
		DEBUG_LOG("STUB: CryptReleaseContext(%p, %u)\n", hProv, dwFlags);
		return TRUE;
	}

	BOOL WIN_FUNC CryptAcquireContextW(void **phProv, const uint16_t *pszContainer, const uint16_t *pszProvider,
					  unsigned int dwProvType, unsigned int dwFlags) {
		DEBUG_LOG("STUB: CryptAcquireContextW(%p, %p, %p, %u, %u)\n", phProv, pszContainer, pszProvider, dwProvType, dwFlags);

		// to quote the guy above me: screw them for now
		static int lmao = 42;
		if (phProv) {
			*phProv = &lmao;
			return TRUE;
		}

		return FALSE;
	}

	BOOL WIN_FUNC CryptGenRandom(void* hProv, unsigned int dwLen, unsigned char* pbBuffer){
		DEBUG_LOG("CryptGenRandom(%p)\n", hProv);
		if (!pbBuffer || dwLen == 0) return FALSE;

		ssize_t ret = getrandom(pbBuffer, dwLen, 0);
		if (ret < 0 || (size_t)ret != dwLen) {
			return FALSE;
		}

		return TRUE;
	}

	BOOL WIN_FUNC CryptCreateHash(void* hProv, unsigned int Algid, void* hKey, unsigned int dwFlags, void** phHash) {
		DEBUG_LOG("CryptCreateHash(%p, %u, %p, %u, %p)\n", hProv, Algid, hKey, dwFlags, phHash);
		(void)hProv;
		if (!phHash) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		if (dwFlags != 0) {
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return FALSE;
		}
		if (hKey != nullptr) {
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
		*phHash = hash;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC CryptHashData(void* hHash, const unsigned char* pbData, unsigned int dwDataLen, unsigned int dwFlags) {
		DEBUG_LOG("CryptHashData(%p, %p, %u, %u)\n", hHash, pbData, dwDataLen, dwFlags);
		if (!hHash || (dwDataLen && !pbData) || dwFlags != 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *hash = reinterpret_cast<HashObject *>(hHash);
		if (pbData && dwDataLen) {
			hash->data.insert(hash->data.end(), pbData, pbData + dwDataLen);
			hash->digestComputed = false;
			hash->digest.clear();
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC CryptGetHashParam(void* hHash, unsigned int dwParam, unsigned char* pbData, unsigned int* pdwDataLen, unsigned int dwFlags) {
		DEBUG_LOG("CryptGetHashParam(%p, %u, %p, %p, %u)\n", hHash, dwParam, pbData, pdwDataLen, dwFlags);
		if (!hHash || !pdwDataLen || dwFlags != 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *hash = reinterpret_cast<HashObject *>(hHash);
		switch (dwParam) {
		case HP_ALGID: {
			unsigned int required = sizeof(ALG_ID);
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
			unsigned int size = 0;
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
				*pdwDataLen = sizeof(unsigned int);
				wibo::lastError = ERROR_SUCCESS;
				return TRUE;
			}
			if (*pdwDataLen < sizeof(unsigned int)) {
				*pdwDataLen = sizeof(unsigned int);
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			memcpy(pbData, &size, sizeof(unsigned int));
			*pdwDataLen = sizeof(unsigned int);
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		case HP_HASHVAL: {
			if (!computeDigest(*hash)) {
				wibo::lastError = ERROR_NOT_SUPPORTED;
				return FALSE;
			}
			unsigned int required = hash->digest.size();
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

	BOOL WIN_FUNC CryptDestroyHash(void* hHash) {
		DEBUG_LOG("CryptDestroyHash(%p)\n", hHash);
		if (!hHash) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		delete reinterpret_cast<HashObject *>(hHash);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE *TokenHandle) {
		DEBUG_LOG("OpenProcessToken(%p, %u, %p)\n", ProcessHandle, DesiredAccess, TokenHandle);
		if (!TokenHandle) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *token = new TokenObject;
		token->processHandle = ProcessHandle;
		token->desiredAccess = DesiredAccess;
		handles::Data data;
		data.type = handles::TYPE_TOKEN;
		data.ptr = token;
		data.size = 0;
		*TokenHandle = handles::allocDataHandle(data);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	void releaseToken(void *tokenPtr) {
		delete reinterpret_cast<TokenObject *>(tokenPtr);
	}

	BOOL WIN_FUNC GetTokenInformation(HANDLE TokenHandle, unsigned int TokenInformationClass, void *TokenInformation, unsigned int TokenInformationLength, unsigned int *ReturnLength) {
		DEBUG_LOG("GetTokenInformation(%p, %u, %p, %u, %p)\n", TokenHandle, TokenInformationClass, TokenInformation,
				  TokenInformationLength, ReturnLength);
		if (!ReturnLength) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto data = handles::dataFromHandle(TokenHandle, false);
		if (data.type != handles::TYPE_TOKEN) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		constexpr unsigned int TokenUserClass = 1; // TokenUser
		constexpr unsigned int TokenStatisticsClass = 10; // TokenStatistics
		constexpr unsigned int TokenElevationClass = 20; // TokenElevation
		constexpr unsigned int TokenPrimaryGroupClass = 5; // TokenPrimaryGroup
		if (TokenInformationClass == TokenUserClass) {
			constexpr size_t sidSize = sizeof(Sid);
			constexpr size_t tokenUserSize = sizeof(TokenUserData);
			const auto required = static_cast<unsigned int>(tokenUserSize + sidSize);
			*ReturnLength = required;
			if (!TokenInformation || TokenInformationLength < required) {
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			auto *tokenUser = reinterpret_cast<TokenUserData *>(TokenInformation);
			auto *sid = reinterpret_cast<Sid *>(reinterpret_cast<uint8_t *>(TokenInformation) + tokenUserSize);
			SidIdentifierAuthority ntAuthority = {{0, 0, 0, 0, 0, 5}};
			sid->Revision = 1;
			sid->SubAuthorityCount = 1;
			sid->IdentifierAuthority = ntAuthority;
			sid->SubAuthority[0] = 18; // SECURITY_LOCAL_SYSTEM_RID
			tokenUser->User.SidPtr = sid;
			tokenUser->User.Attributes = 0;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (TokenInformationClass == TokenStatisticsClass) {
			const unsigned int required = sizeof(TokenStatisticsData);
			*ReturnLength = required;
			if (!TokenInformation || TokenInformationLength < required) {
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			auto *stats = reinterpret_cast<TokenStatisticsData *>(TokenInformation);
			*stats = {};
			stats->tokenType = 1; // TokenPrimary
			stats->impersonationLevel = 0; // SecurityAnonymous
			stats->tokenId.LowPart = 1;
			stats->authenticationId.LowPart = 1;
			stats->modifiedId.LowPart = 1;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (TokenInformationClass == TokenElevationClass) {
			const unsigned int required = sizeof(DWORD);
			*ReturnLength = required;
			if (!TokenInformation || TokenInformationLength < required) {
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			*reinterpret_cast<DWORD *>(TokenInformation) = 0; // not elevated
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		if (TokenInformationClass == TokenPrimaryGroupClass) {
			struct TokenPrimaryGroupStub {
				Sid *PrimaryGroup;
			};
			constexpr size_t sidSize = sizeof(Sid);
			constexpr size_t headerSize = sizeof(TokenPrimaryGroupStub);
			const unsigned int required = static_cast<unsigned int>(headerSize + sidSize);
			*ReturnLength = required;
			if (!TokenInformation || TokenInformationLength < required) {
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			auto *groupInfo = reinterpret_cast<TokenPrimaryGroupStub *>(TokenInformation);
			auto *sid = reinterpret_cast<Sid *>(reinterpret_cast<uint8_t *>(TokenInformation) + headerSize);
			sid->Revision = 1;
			sid->SubAuthorityCount = 1;
			sid->IdentifierAuthority = {{0, 0, 0, 0, 0, 5}};
			sid->SubAuthority[0] = 18; // SECURITY_LOCAL_SYSTEM_RID
			groupInfo->PrimaryGroup = sid;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}

	BOOL WIN_FUNC LookupAccountSidW(const uint16_t *lpSystemName, const void *sidPointer, uint16_t *Name,
									unsigned long *cchName, uint16_t *ReferencedDomainName,
									unsigned long *cchReferencedDomainName, SID_NAME_USE *peUse) {
		std::string systemName = lpSystemName ? wideStringToString(lpSystemName) : std::string("(null)");
		DEBUG_LOG("LookupAccountSidW(%s, %p, %p, %p, %p, %p, %p)\n", systemName.c_str(), sidPointer, Name, cchName,
				  ReferencedDomainName, cchReferencedDomainName, peUse);
		(void) lpSystemName; // Only local lookup supported
		if (!sidPointer || !cchName || !cchReferencedDomainName || !peUse) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *sid = reinterpret_cast<const Sid *>(sidPointer);
		if (!isLocalSystemSid(sid)) {
			wibo::lastError = ERROR_NONE_MAPPED;
			return FALSE;
		}
		static constexpr uint16_t accountName[] = {u'S', u'Y', u'S', u'T', u'E', u'M', u'\0'};
		static constexpr uint16_t domainName[] = {u'N', u'T', u' ', u'A', u'U', u'T', u'H', u'O', u'R', u'I', u'T', u'Y', u'\0'};
		unsigned long requiredAccount = wstrlen(accountName) + 1;
		unsigned long requiredDomain = wstrlen(domainName) + 1;
		if (!Name || *cchName < requiredAccount || !ReferencedDomainName || *cchReferencedDomainName < requiredDomain) {
			*cchName = requiredAccount;
			*cchReferencedDomainName = requiredDomain;
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		std::copy_n(accountName, requiredAccount, Name);
		std::copy_n(domainName, requiredDomain, ReferencedDomainName);
		*peUse = SidTypeWellKnownGroup;
		*cchName = requiredAccount - 1;
		*cchReferencedDomainName = requiredDomain - 1;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	static Luid generateDeterministicLuid(const std::string &normalizedName) {
		uint32_t hash = 2166136261u;
		for (unsigned char ch : normalizedName) {
			hash ^= ch;
			hash *= 16777619u;
		}
		if (hash == 0) {
			hash = 1;
		}
		Luid result{};
		result.LowPart = hash;
		result.HighPart = 0;
		return result;
	}

	static std::string normalizePrivilegeName(const std::string &name) {
		std::string normalized;
		normalized.reserve(name.size());
		for (unsigned char ch : name) {
			if (ch == '\r' || ch == '\n' || ch == '\t') {
				continue;
			}
			normalized.push_back(static_cast<char>(std::tolower(ch)));
		}
		return normalized;
	}

	static Luid lookupOrGeneratePrivilegeLuid(const std::string &normalizedName) {
		std::lock_guard<std::mutex> lock(privilegeMapMutex);
		auto cached = privilegeLuidCache.find(normalizedName);
		if (cached != privilegeLuidCache.end()) {
			return cached->second;
		}
		static const std::unordered_map<std::string, uint32_t> predefined = {
			{"secreatepagefileprivilege", 0x00000002},
			{"seshutdownprivilege", 0x00000003},
			{"sebackupprivilege", 0x00000004},
			{"serestoreprivilege", 0x00000005},
			{"sechangenotifyprivilege", 0x00000006},
			{"seassignprimarytokenprivilege", 0x00000007},
			{"seincreasequotaprivilege", 0x00000008},
			{"seincreasebasepriorityprivilege", 0x00000009},
			{"seloaddriverprivilege", 0x0000000a},
			{"setakeownershipprivilege", 0x0000000b},
			{"sesystemtimeprivilege", 0x0000000c},
			{"sesystemenvironmentprivilege", 0x0000000d},
			{"setcbprivilege", 0x0000000e},
			{"sedebugprivilege", 0x0000000f},
			{"semanagevolumeprivilege", 0x00000010},
			{"seimpersonateprivilege", 0x00000011},
			{"secreateglobalprivilege", 0x00000012},
			{"sesecurityprivilege", 0x00000013},
			{"selockmemoryprivilege", 0x00000014},
			{"seundockprivilege", 0x00000015},
			{"seremoteshutdownprivilege", 0x00000016}
		};
		auto known = predefined.find(normalizedName);
		Luid luid{};
		if (known != predefined.end()) {
			luid.LowPart = known->second;
			luid.HighPart = 0;
		} else {
			luid = generateDeterministicLuid(normalizedName);
		}
		privilegeLuidCache.emplace(normalizedName, luid);
		return luid;
	}

	BOOL WIN_FUNC LookupPrivilegeValueA(const char *lpSystemName, const char *lpName, Luid *lpLuid) {
		DEBUG_LOG("LookupPrivilegeValueA(%s, %s, %p)\n",
			lpSystemName ? lpSystemName : "<null>",
			lpName ? lpName : "<null>",
			lpLuid);
		if (!lpName || !lpLuid) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		if (lpSystemName && lpSystemName[0] != '\0') {
			DEBUG_LOG("-> remote system unsupported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return FALSE;
		}
		std::string normalized = normalizePrivilegeName(lpName);
		if (normalized.empty()) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		Luid luid = lookupOrGeneratePrivilegeLuid(normalized);
		*lpLuid = luid;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC LookupPrivilegeValueW(const uint16_t *lpSystemName, const uint16_t *lpName, Luid *lpLuid) {
		DEBUG_LOG("LookupPrivilegeValueW(%ls, %ls, %p)\n",
			lpSystemName ? reinterpret_cast<const wchar_t *>(lpSystemName) : L"<null>",
			lpName ? reinterpret_cast<const wchar_t *>(lpName) : L"<null>",
			lpLuid);
		if (!lpName || !lpLuid) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		if (lpSystemName && lpSystemName[0] != 0) {
			std::string host = wideStringToString(lpSystemName);
			if (!host.empty()) {
				wibo::lastError = ERROR_NOT_SUPPORTED;
				return FALSE;
			}
		}
		std::string ansiName = wideStringToString(lpName);
		return LookupPrivilegeValueA(nullptr, ansiName.c_str(), lpLuid);
	}

	struct TokenPrivilegesHeader {
		DWORD PrivilegeCount = 0;
	};

	BOOL WIN_FUNC AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, void *NewState, DWORD BufferLength,
										 void *PreviousState, PDWORD ReturnLength) {
		DEBUG_LOG("AdjustTokenPrivileges(%p, %d, %p, %u, %p, %p)\n", TokenHandle, DisableAllPrivileges,
				  NewState, BufferLength, PreviousState, ReturnLength);
		(void) DisableAllPrivileges;
		(void) NewState;
		auto data = handles::dataFromHandle(TokenHandle, false);
		if (data.type != handles::TYPE_TOKEN) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		if (PreviousState) {
			if (BufferLength < sizeof(TokenPrivilegesHeader)) {
				if (ReturnLength) {
					*ReturnLength = sizeof(TokenPrivilegesHeader);
				}
				wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
				return FALSE;
			}
			auto *header = reinterpret_cast<TokenPrivilegesHeader *>(PreviousState);
			header->PrivilegeCount = 0;
			if (ReturnLength) {
				*ReturnLength = sizeof(TokenPrivilegesHeader);
			}
		} else if (ReturnLength) {
			*ReturnLength = 0;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC InitializeSecurityDescriptor(void *pSecurityDescriptor, DWORD dwRevision) {
		DEBUG_LOG("InitializeSecurityDescriptor(%p, %u)\n", pSecurityDescriptor, dwRevision);
		if (!pSecurityDescriptor) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		if (dwRevision != SECURITY_DESCRIPTOR_REVISION) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *descriptor = static_cast<SecurityDescriptor *>(pSecurityDescriptor);
		descriptor->Revision = static_cast<uint8_t>(dwRevision);
		descriptor->Sbz1 = 0;
		descriptor->Control = 0;
		descriptor->Owner = nullptr;
		descriptor->Group = nullptr;
		descriptor->Sacl = nullptr;
		descriptor->Dacl = nullptr;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC SetSecurityDescriptorDacl(void *pSecurityDescriptor, BOOL bDaclPresent, void *pDacl, BOOL bDaclDefaulted) {
		DEBUG_LOG("SetSecurityDescriptorDacl(%p, %u, %p, %u)\n", pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted);
		if (!pSecurityDescriptor) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		auto *descriptor = static_cast<SecurityDescriptor *>(pSecurityDescriptor);
		if (descriptor->Revision != SECURITY_DESCRIPTOR_REVISION) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		uint16_t control = static_cast<uint16_t>(descriptor->Control & ~(SE_DACL_PRESENT | SE_DACL_DEFAULTED));
		if (bDaclPresent) {
			control = static_cast<uint16_t>(control | SE_DACL_PRESENT);
			if (bDaclDefaulted) {
				control = static_cast<uint16_t>(control | SE_DACL_DEFAULTED);
			}
			descriptor->Dacl = pDacl;
		} else {
			descriptor->Dacl = nullptr;
		}
		descriptor->Control = control;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC GetUserNameA(char *lpBuffer, DWORD *pcbBuffer) {
		DEBUG_LOG("GetUserNameA(%p, %p)\n", lpBuffer, pcbBuffer);
		if (!pcbBuffer) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		const char *name = "SYSTEM";
		size_t needed = std::strlen(name) + 1;
		if (!lpBuffer || *pcbBuffer < needed) {
			*pcbBuffer = static_cast<DWORD>(needed);
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		std::memcpy(lpBuffer, name, needed);
		*pcbBuffer = static_cast<DWORD>(needed);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC GetUserNameW(uint16_t *lpBuffer, DWORD *pcbBuffer) {
		DEBUG_LOG("GetUserNameW(%p, %p)\n", lpBuffer, pcbBuffer);
		if (!pcbBuffer) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		const char16_t name[] = {u'S', u'Y', u'S', u'T', u'E', u'M', u'\0'};
		size_t needed = (std::size(name));
		if (!lpBuffer || *pcbBuffer < needed) {
			*pcbBuffer = static_cast<DWORD>(needed);
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		std::memcpy(lpBuffer, name, needed * sizeof(uint16_t));
		*pcbBuffer = static_cast<DWORD>(needed);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC SetTokenInformation(HANDLE TokenHandle, unsigned int TokenInformationClass, void *TokenInformation, DWORD TokenInformationLength) {
		DEBUG_LOG("STUB: SetTokenInformation(%p, %u, %p, %u)\n", TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength);
		(void) TokenInformationClass;
		(void) TokenInformation;
		(void) TokenInformationLength;
		auto data = handles::dataFromHandle(TokenHandle, false);
		if (data.type != handles::TYPE_TOKEN) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "RegOpenKeyExA") == 0) return (void *) advapi32::RegOpenKeyExA;
	if (strcmp(name, "RegOpenKeyExW") == 0) return (void *) advapi32::RegOpenKeyExW;
	if (strcmp(name, "RegCloseKey") == 0) return (void *) advapi32::RegCloseKey;
	if (strcmp(name, "CryptReleaseContext") == 0) return (void*) advapi32::CryptReleaseContext;
	if (strcmp(name, "CryptAcquireContextW") == 0) return (void*) advapi32::CryptAcquireContextW;
	if (strcmp(name, "CryptGenRandom") == 0) return (void*) advapi32::CryptGenRandom;
	if (strcmp(name, "CryptCreateHash") == 0) return (void*) advapi32::CryptCreateHash;
	if (strcmp(name, "CryptHashData") == 0) return (void*) advapi32::CryptHashData;
	if (strcmp(name, "CryptGetHashParam") == 0) return (void*) advapi32::CryptGetHashParam;
	if (strcmp(name, "CryptDestroyHash") == 0) return (void*) advapi32::CryptDestroyHash;
	if (strcmp(name, "OpenProcessToken") == 0) return (void*) advapi32::OpenProcessToken;
	if (strcmp(name, "GetTokenInformation") == 0) return (void*) advapi32::GetTokenInformation;
	if (strcmp(name, "LookupAccountSidW") == 0) return (void*) advapi32::LookupAccountSidW;
	if (strcmp(name, "InitializeSecurityDescriptor") == 0) return (void*) advapi32::InitializeSecurityDescriptor;
	if (strcmp(name, "SetSecurityDescriptorDacl") == 0) return (void*) advapi32::SetSecurityDescriptorDacl;
	if (strcmp(name, "LookupPrivilegeValueA") == 0) return (void*) advapi32::LookupPrivilegeValueA;
	if (strcmp(name, "LookupPrivilegeValueW") == 0) return (void*) advapi32::LookupPrivilegeValueW;
	if (strcmp(name, "AdjustTokenPrivileges") == 0) return (void*) advapi32::AdjustTokenPrivileges;
	if (strcmp(name, "GetUserNameA") == 0) return (void*) advapi32::GetUserNameA;
	if (strcmp(name, "GetUserNameW") == 0) return (void*) advapi32::GetUserNameW;
	if (strcmp(name, "SetTokenInformation") == 0) return (void*) advapi32::SetTokenInformation;
	return nullptr;
}

wibo::Module lib_advapi32 = {
	(const char *[]){
		"advapi32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
