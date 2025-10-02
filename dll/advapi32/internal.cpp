#include "internal.h"

#include <cctype>
#include <mutex>
#include <unordered_map>

namespace {

constexpr DWORD SECURITY_LOCAL_SYSTEM_RID = 18;

constexpr BYTE kNtAuthority[6] = {0, 0, 0, 0, 0, 5};

std::mutex privilegeMapMutex;
std::unordered_map<std::string, LUID> privilegeLuidCache;

LUID generateDeterministicLuid(const std::string &normalizedName) {
	uint32_t hash = 2166136261u;
	for (unsigned char ch : normalizedName) {
		hash ^= ch;
		hash *= 16777619u;
	}
	if (hash == 0) {
		hash = 1;
	}
	LUID luid{};
	luid.LowPart = hash;
	luid.HighPart = 0;
	return luid;
}

} // namespace

namespace advapi32 {

bool isLocalSystemSid(const Sid *sid) {
	if (!sid) {
		return false;
	}
	if (sid->Revision != 1 || sid->SubAuthorityCount != 1) {
		return false;
	}
	for (size_t i = 0; i < std::size(kNtAuthority); ++i) {
		if (sid->IdentifierAuthority.Value[i] != kNtAuthority[i]) {
			return false;
		}
	}
	return sid->SubAuthority[0] == SECURITY_LOCAL_SYSTEM_RID;
}

bool writeLocalSystemSid(Sid *sid) {
	if (!sid) {
		return false;
	}
	sid->Revision = 1;
	sid->SubAuthorityCount = 1;
	SidIdentifierAuthority authority{};
	for (size_t i = 0; i < std::size(kNtAuthority); ++i) {
		authority.Value[i] = kNtAuthority[i];
	}
	sid->IdentifierAuthority = authority;
	sid->SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;
	return true;
}

std::string normalizePrivilegeName(const std::string &name) {
	std::string normalized;
	normalized.reserve(name.size());
	for (unsigned char ch : name) {
		normalized.push_back(static_cast<char>(std::tolower(ch)));
	}
	return normalized;
}

LUID lookupOrGeneratePrivilegeLuid(const std::string &normalizedName) {
	std::lock_guard<std::mutex> lock(privilegeMapMutex);
	static const std::unordered_map<std::string, uint32_t> predefined = {
		{"se_debug_name", 0x14},
		{"se_shutdown_name", 0x13},
	};
	auto it = privilegeLuidCache.find(normalizedName);
	if (it != privilegeLuidCache.end()) {
		return it->second;
	}
	LUID luid{};
	auto predefinedIt = predefined.find(normalizedName);
	if (predefinedIt != predefined.end()) {
		luid.LowPart = predefinedIt->second;
		luid.HighPart = 0;
	} else {
		luid = generateDeterministicLuid(normalizedName);
	}
	privilegeLuidCache[normalizedName] = luid;
	return luid;
}

void releaseToken(void *tokenPtr) { delete reinterpret_cast<TokenObject *>(tokenPtr); }

} // namespace advapi32
