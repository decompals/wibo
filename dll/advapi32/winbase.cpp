#include "winbase.h"

#include "errors.h"
#include "internal.h"
#include "strutil.h"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace {

constexpr WCHAR kAccountSystem[] = {u'S', u'Y', u'S', u'T', u'E', u'M', u'\0'};
constexpr WCHAR kDomainNtAuthority[] = {u'N', u'T', u' ', u'A', u'U', u'T', u'H', u'O', u'R', u'I', u'T', u'Y', u'\0'};

std::mutex g_privilegeMapMutex;
std::unordered_map<std::string, LUID> g_privilegeLuidCache;

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

std::string normalizePrivilegeName(const std::string &name) {
	std::string normalized;
	normalized.reserve(name.size());
	for (unsigned char ch : name) {
		normalized.push_back(static_cast<char>(std::tolower(ch)));
	}
	return normalized;
}

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

LUID lookupOrGeneratePrivilegeLuid(const std::string &normalizedName) {
	std::lock_guard<std::mutex> lock(g_privilegeMapMutex);
	static const std::unordered_map<std::string, uint32_t> predefined = {
		{"se_debug_name", 0x14},
		{"se_shutdown_name", 0x13},
	};
	auto it = g_privilegeLuidCache.find(normalizedName);
	if (it != g_privilegeLuidCache.end()) {
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
	g_privilegeLuidCache[normalizedName] = luid;
	return luid;
}

} // namespace

namespace advapi32 {

BOOL WIN_FUNC LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName,
								LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, SID_NAME_USE *peUse) {
	std::string systemName = lpSystemName ? wideStringToString(lpSystemName) : std::string("(null)");
	DEBUG_LOG("LookupAccountSidW(%s, %p, %p, %p, %p, %p, %p)\n", systemName.c_str(), Sid, Name, cchName,
			  ReferencedDomainName, cchReferencedDomainName, peUse);
	if (!Sid || !cchName || !cchReferencedDomainName || !peUse) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto *sidStruct = reinterpret_cast<const struct Sid *>(Sid);
	if (!isLocalSystemSid(sidStruct)) {
		wibo::lastError = ERROR_NONE_MAPPED;
		return FALSE;
	}
	DWORD requiredAccount = static_cast<DWORD>(wstrlen(kAccountSystem));
	DWORD requiredDomain = static_cast<DWORD>(wstrlen(kDomainNtAuthority));
	if (!Name || *cchName <= requiredAccount || !ReferencedDomainName || *cchReferencedDomainName <= requiredDomain) {
		*cchName = requiredAccount + 1;
		*cchReferencedDomainName = requiredDomain + 1;
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return FALSE;
	}
	std::copy_n(kAccountSystem, requiredAccount + 1, Name);
	std::copy_n(kDomainNtAuthority, requiredDomain + 1, ReferencedDomainName);
	*peUse = SidTypeWellKnownGroup;
	*cchName = requiredAccount;
	*cchReferencedDomainName = requiredDomain;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid) {
	DEBUG_LOG("LookupPrivilegeValueA(%s, %s, %p)\n", lpSystemName ? lpSystemName : "(null)", lpName ? lpName : "(null)",
			  lpLuid);
	(void)lpSystemName; // only local lookup supported
	if (!lpName || !lpLuid) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string normalized = normalizePrivilegeName(lpName);
	LUID luid = lookupOrGeneratePrivilegeLuid(normalized);
	*lpLuid = luid;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid) {
	DEBUG_LOG("LookupPrivilegeValueW(%p, %p, %p)\n", lpSystemName, lpName, lpLuid);
	(void)lpSystemName; // only local lookup supported
	if (!lpName || !lpLuid) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string ansiName = wideStringToString(lpName);
	std::string normalized = normalizePrivilegeName(ansiName);
	LUID luid = lookupOrGeneratePrivilegeLuid(normalized);
	*lpLuid = luid;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer) {
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

BOOL WIN_FUNC GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer) {
	DEBUG_LOG("GetUserNameW(%p, %p)\n", lpBuffer, pcbBuffer);
	if (!pcbBuffer) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	size_t needed = wstrlen(kAccountSystem) + 1;
	if (!lpBuffer || *pcbBuffer < needed) {
		*pcbBuffer = static_cast<DWORD>(needed);
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return FALSE;
	}
	std::memcpy(lpBuffer, kAccountSystem, needed * sizeof(WCHAR));
	*pcbBuffer = static_cast<DWORD>(needed);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace advapi32
