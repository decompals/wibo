#include "common.h"
#include "advapi32/winreg.h"
#include "advapi32/wincrypt.h"
#include "errors.h"
#include "handles.h"
#include "strutil.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {
	struct Luid;
	static std::mutex privilegeMapMutex;
	static std::unordered_map<std::string, Luid> privilegeLuidCache;

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

}

namespace advapi32 {
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
	// winreg.h
	if (strcmp(name, "RegOpenKeyExA") == 0) return (void *) advapi32::RegOpenKeyExA;
	if (strcmp(name, "RegOpenKeyExW") == 0) return (void *) advapi32::RegOpenKeyExW;
	if (strcmp(name, "RegCloseKey") == 0) return (void *) advapi32::RegCloseKey;
	// wincrypt.h
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
