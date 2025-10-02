#include "securitybaseapi.h"

#include "errors.h"
#include "handles.h"
#include "internal.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace {

constexpr size_t kAceAlignment = 4;
constexpr DWORD ERROR_REVISION_MISMATCH = 1306;
constexpr DWORD ERROR_INVALID_ACL = 1336;
constexpr DWORD ERROR_INVALID_SID = 1337;
constexpr DWORD ERROR_ALLOTTED_SPACE_EXCEEDED = 1344;
constexpr DWORD ERROR_INVALID_SECURITY_DESCR = 1338;

struct SidAndAttributes {
	Sid *SidPtr;
	DWORD Attributes;
};

struct TokenUserData {
	SidAndAttributes User;
};

struct TokenStatisticsData {
	LUID tokenId{};
	LUID authenticationId{};
	LARGE_INTEGER expirationTime{};
	DWORD tokenType = 0;
	DWORD impersonationLevel = 0;
	DWORD dynamicCharged = 0;
	DWORD dynamicAvailable = 0;
	DWORD groupCount = 0;
	DWORD privilegeCount = 0;
	LUID modifiedId{};
};

struct TokenPrimaryGroupStub {
	Sid *PrimaryGroup;
};

size_t alignToDword(size_t value) { return (value + (kAceAlignment - 1)) & ~(kAceAlignment - 1); }

size_t sidLength(const Sid *sid) {
	if (!sid) {
		return 0;
	}
	if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES) {
		return 0;
	}
	size_t base = sizeof(Sid) - sizeof(DWORD);
	size_t extra = static_cast<size_t>(sid->SubAuthorityCount) * sizeof(DWORD);
	return base + extra;
}

bool computeAclUsedSize(const ACL *acl, size_t capacity, size_t &used) {
	if (!acl || capacity < sizeof(ACL)) {
		return false;
	}
	size_t offset = sizeof(ACL);
	const BYTE *base = reinterpret_cast<const BYTE *>(acl);
	for (WORD i = 0; i < acl->AceCount; ++i) {
		if (offset + sizeof(ACE_HEADER) > capacity) {
			return false;
		}
		const auto *header = reinterpret_cast<const ACE_HEADER *>(base + offset);
		if (header->AceSize < sizeof(ACE_HEADER)) {
			return false;
		}
		size_t aceSize = header->AceSize;
		if (offset + aceSize > capacity) {
			return false;
		}
		offset += aceSize;
	}
	used = offset;
	return true;
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

} // namespace

namespace advapi32 {

BOOL WIN_FUNC InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision) {
	DEBUG_LOG("InitializeAcl(%p, %u, %u)\n", pAcl, nAclLength, dwAclRevision);
	if (!pAcl) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (nAclLength < sizeof(ACL) || nAclLength > std::numeric_limits<WORD>::max() || (nAclLength & 0x3) != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	BYTE revision = static_cast<BYTE>(dwAclRevision);
	switch (revision) {
	case ACL_REVISION1:
	case ACL_REVISION2:
	case ACL_REVISION3:
	case ACL_REVISION4:
		break;
	default:
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	pAcl->AclRevision = revision;
	pAcl->Sbz1 = 0;
	pAcl->AclSize = static_cast<WORD>(sizeof(ACL));
	pAcl->AceCount = 0;
	pAcl->Sbz2 = static_cast<WORD>(nAclLength);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC AddAccessAllowedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid) {
	DEBUG_LOG("AddAccessAllowedAce(%p, %u, 0x%x, %p)\n", pAcl, dwAceRevision, AccessMask, pSid);
	if (!pAcl || !pSid) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	BYTE revision = static_cast<BYTE>(dwAceRevision);
	switch (revision) {
	case ACL_REVISION1:
	case ACL_REVISION2:
	case ACL_REVISION3:
	case ACL_REVISION4:
		break;
	default:
		wibo::lastError = ERROR_REVISION_MISMATCH;
		return FALSE;
	}
	if (pAcl->AclRevision < revision) {
		wibo::lastError = ERROR_REVISION_MISMATCH;
		return FALSE;
	}
	if (pAcl->AceCount == std::numeric_limits<WORD>::max()) {
		wibo::lastError = ERROR_ALLOTTED_SPACE_EXCEEDED;
		return FALSE;
	}
	size_t capacity = pAcl->Sbz2 ? pAcl->Sbz2 : pAcl->AclSize;
	if (capacity < sizeof(ACL)) {
		wibo::lastError = ERROR_INVALID_ACL;
		return FALSE;
	}
	size_t used = 0;
	if (!computeAclUsedSize(pAcl, capacity, used)) {
		wibo::lastError = ERROR_INVALID_ACL;
		return FALSE;
	}
	if (used > pAcl->AclSize) {
		// Clamp to the computed size to avoid propagating inconsistent data.
		pAcl->AclSize = static_cast<WORD>(used);
	}
	const auto *sid = reinterpret_cast<const Sid *>(pSid);
	size_t sidLen = sidLength(sid);
	if (sidLen == 0 || sidLen > capacity) {
		wibo::lastError = ERROR_INVALID_SID;
		return FALSE;
	}
	size_t aceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLen;
	aceSize = alignToDword(aceSize);
	if (aceSize > std::numeric_limits<WORD>::max()) {
		wibo::lastError = ERROR_INVALID_SID;
		return FALSE;
	}
	if (used + aceSize > capacity) {
		wibo::lastError = ERROR_ALLOTTED_SPACE_EXCEEDED;
		return FALSE;
	}
	auto *dest = reinterpret_cast<BYTE *>(pAcl) + used;
	std::memset(dest, 0, aceSize);
	auto *ace = reinterpret_cast<ACCESS_ALLOWED_ACE *>(dest);
	ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
	ace->Header.AceFlags = 0;
	ace->Header.AceSize = static_cast<WORD>(aceSize);
	ace->Mask = AccessMask;
	std::memcpy(&ace->SidStart, sid, sidLen);
	pAcl->AceCount = static_cast<WORD>(pAcl->AceCount + 1);
	pAcl->AclSize = static_cast<WORD>(used + aceSize);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC FindFirstFreeAce(PACL pAcl, LPVOID *pAce) {
	DEBUG_LOG("FindFirstFreeAce(%p, %p)\n", pAcl, pAce);
	if (!pAce) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*pAce = nullptr;
	if (!pAcl) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	size_t capacity = pAcl->Sbz2 ? pAcl->Sbz2 : pAcl->AclSize;
	size_t used = 0;
	if (!computeAclUsedSize(pAcl, capacity, used)) {
		wibo::lastError = ERROR_INVALID_ACL;
		return FALSE;
	}
	*pAce = reinterpret_cast<BYTE *>(pAcl) + used;
	pAcl->AclSize = static_cast<WORD>(std::max<size_t>(pAcl->AclSize, used));
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl,
										LPBOOL lpbDaclDefaulted) {
	DEBUG_LOG("GetSecurityDescriptorDacl(%p, %p, %p, %p)\n", pSecurityDescriptor, lpbDaclPresent, pDacl,
			  lpbDaclDefaulted);
	if (!pSecurityDescriptor) {
		wibo::lastError = ERROR_INVALID_SECURITY_DESCR;
		return FALSE;
	}
	if (!lpbDaclPresent) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (pSecurityDescriptor->Revision != SECURITY_DESCRIPTOR_REVISION) {
		wibo::lastError = ERROR_INVALID_SECURITY_DESCR;
		return FALSE;
	}
	BOOL hasDacl = (pSecurityDescriptor->Control & SE_DACL_PRESENT) ? TRUE : FALSE;
	*lpbDaclPresent = hasDacl;
	if (!hasDacl) {
		if (pDacl) {
			*pDacl = nullptr;
		}
		if (lpbDaclDefaulted) {
			*lpbDaclDefaulted = FALSE;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (pDacl) {
		*pDacl = pSecurityDescriptor->Dacl;
	}
	if (lpbDaclDefaulted) {
		*lpbDaclDefaulted = (pSecurityDescriptor->Control & SE_DACL_DEFAULTED) ? TRUE : FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

PSID_IDENTIFIER_AUTHORITY WIN_FUNC GetSidIdentifierAuthority(PSID pSid) {
	DEBUG_LOG("GetSidIdentifierAuthority(%p)\n", pSid);
	if (!pSid) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	auto *sid = reinterpret_cast<Sid *>(pSid);
	if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return reinterpret_cast<PSID_IDENTIFIER_AUTHORITY>(&sid->IdentifierAuthority);
}

PUCHAR WIN_FUNC GetSidSubAuthorityCount(PSID pSid) {
	DEBUG_LOG("GetSidSubAuthorityCount(%p)\n", pSid);
	if (!pSid) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	auto *sid = reinterpret_cast<Sid *>(pSid);
	if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return &sid->SubAuthorityCount;
}

PDWORD WIN_FUNC GetSidSubAuthority(PSID pSid, DWORD nSubAuthority) {
	DEBUG_LOG("GetSidSubAuthority(%p, %u)\n", pSid, nSubAuthority);
	if (!pSid) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	auto *sid = reinterpret_cast<Sid *>(pSid);
	if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES || nSubAuthority >= sid->SubAuthorityCount) {
		wibo::lastError = ERROR_INVALID_SID;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return &sid->SubAuthority[nSubAuthority];
}

BOOL WIN_FUNC ImpersonateLoggedOnUser(HANDLE hToken) {
	DEBUG_LOG("STUB: ImpersonateLoggedOnUser(%p)\n", hToken);
	(void)hToken;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, void *lpTokenAttributes,
							   DWORD ImpersonationLevel, DWORD TokenType, PHANDLE phNewToken) {
	DEBUG_LOG("DuplicateTokenEx(%p, 0x%x, %p, %u, %u, %p)\n", hExistingToken, dwDesiredAccess, lpTokenAttributes,
			  ImpersonationLevel, TokenType, phNewToken);
	(void)lpTokenAttributes;
	(void)ImpersonationLevel;
	(void)TokenType;
	if (!phNewToken) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	handles::Data existingData = handles::dataFromHandle(hExistingToken, false);
	if (existingData.type != handles::TYPE_TOKEN || existingData.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	auto *existingToken = static_cast<TokenObject *>(existingData.ptr);
	auto *newToken = new TokenObject(*existingToken);
	if (dwDesiredAccess != 0) {
		newToken->desiredAccess = dwDesiredAccess;
	}
	handles::Data newData;
	newData.type = handles::TYPE_TOKEN;
	newData.ptr = newToken;
	newData.size = sizeof(TokenObject);
	*phNewToken = handles::allocDataHandle(newData);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CopySid(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid) {
	DEBUG_LOG("CopySid(%u, %p, %p)\n", nDestinationSidLength, pDestinationSid, pSourceSid);
	if (!pDestinationSid || !pSourceSid) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto *source = reinterpret_cast<Sid *>(pSourceSid);
	size_t required = sidLength(source);
	if (required == 0 || required > nDestinationSidLength) {
		wibo::lastError = ERROR_ALLOTTED_SPACE_EXCEEDED;
		return FALSE;
	}
	std::memcpy(pDestinationSid, pSourceSid, required);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetKernelObjectSecurity(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
									  PSECURITY_DESCRIPTOR SecurityDescriptor) {
	DEBUG_LOG("STUB: SetKernelObjectSecurity(%p, 0x%x, %p)\n", Handle, SecurityInformation, SecurityDescriptor);
	(void)SecurityInformation;
	if (!SecurityDescriptor) {
		wibo::lastError = ERROR_INVALID_SECURITY_DESCR;
		return FALSE;
	}
	auto data = handles::dataFromHandle(Handle, false);
	if (data.type == handles::TYPE_UNUSED) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision) {
	DEBUG_LOG("InitializeSecurityDescriptor(%p, %u)\n", pSecurityDescriptor, dwRevision);
	if (!pSecurityDescriptor || dwRevision != SECURITY_DESCRIPTOR_REVISION) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	pSecurityDescriptor->Revision = static_cast<BYTE>(dwRevision);
	pSecurityDescriptor->Sbz1 = 0;
	pSecurityDescriptor->Control = 0;
	pSecurityDescriptor->Owner = nullptr;
	pSecurityDescriptor->Group = nullptr;
	pSecurityDescriptor->Sacl = nullptr;
	pSecurityDescriptor->Dacl = nullptr;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl,
										BOOL bDaclDefaulted) {
	DEBUG_LOG("SetSecurityDescriptorDacl(%p, %u, %p, %u)\n", pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted);
	if (!pSecurityDescriptor || pSecurityDescriptor->Revision != SECURITY_DESCRIPTOR_REVISION) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	WORD control = static_cast<WORD>(pSecurityDescriptor->Control & ~(SE_DACL_PRESENT | SE_DACL_DEFAULTED));
	if (bDaclPresent) {
		control = static_cast<WORD>(control | SE_DACL_PRESENT);
		if (bDaclDefaulted) {
			control = static_cast<WORD>(control | SE_DACL_DEFAULTED);
		}
		pSecurityDescriptor->Dacl = pDacl;
	} else {
		pSecurityDescriptor->Dacl = nullptr;
	}
	pSecurityDescriptor->Control = control;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
								  LPVOID TokenInformation, DWORD TokenInformationLength, LPDWORD ReturnLength) {
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
	*ReturnLength = 0;
	if (TokenInformationClass == TOKEN_INFORMATION_CLASS::TokenUser) {
		constexpr size_t sidSize = sizeof(Sid);
		constexpr size_t tokenUserSize = sizeof(TokenUserData);
		DWORD required = static_cast<DWORD>(tokenUserSize + sidSize);
		*ReturnLength = required;
		if (!TokenInformation || TokenInformationLength < required) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		auto *tokenUser = reinterpret_cast<TokenUserData *>(TokenInformation);
		auto *sid = reinterpret_cast<Sid *>(reinterpret_cast<BYTE *>(TokenInformation) + tokenUserSize);
		if (!writeLocalSystemSid(sid)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		tokenUser->User.SidPtr = sid;
		tokenUser->User.Attributes = 0;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (TokenInformationClass == TOKEN_INFORMATION_CLASS::TokenStatistics) {
		DWORD required = sizeof(TokenStatisticsData);
		*ReturnLength = required;
		if (!TokenInformation || TokenInformationLength < required) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		auto *stats = reinterpret_cast<TokenStatisticsData *>(TokenInformation);
		*stats = TokenStatisticsData{};
		stats->tokenType = 1;		   // TokenPrimary
		stats->impersonationLevel = 0; // SecurityAnonymous
		stats->tokenId.LowPart = 1;
		stats->authenticationId.LowPart = 1;
		stats->modifiedId.LowPart = 1;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (TokenInformationClass == TOKEN_INFORMATION_CLASS::TokenElevation) {
		DWORD required = sizeof(DWORD);
		*ReturnLength = required;
		if (!TokenInformation || TokenInformationLength < required) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		*reinterpret_cast<DWORD *>(TokenInformation) = 0; // not elevated
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (TokenInformationClass == TOKEN_INFORMATION_CLASS::TokenPrimaryGroup) {
		DWORD required = static_cast<DWORD>(sizeof(TokenPrimaryGroupStub) + sizeof(Sid));
		*ReturnLength = required;
		if (!TokenInformation || TokenInformationLength < required) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return FALSE;
		}
		auto *groupInfo = reinterpret_cast<TokenPrimaryGroupStub *>(TokenInformation);
		auto *sid = reinterpret_cast<Sid *>(reinterpret_cast<BYTE *>(TokenInformation) + sizeof(TokenPrimaryGroupStub));
		if (!writeLocalSystemSid(sid)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		groupInfo->PrimaryGroup = sid;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	wibo::lastError = ERROR_NOT_SUPPORTED;
	return FALSE;
}

BOOL WIN_FUNC AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
									DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, LPDWORD ReturnLength) {
	DEBUG_LOG("AdjustTokenPrivileges(%p, %u, %p, %u, %p, %p)\n", TokenHandle, DisableAllPrivileges, NewState,
			  BufferLength, PreviousState, ReturnLength);
	(void)TokenHandle;
	(void)DisableAllPrivileges;
	(void)NewState;
	(void)BufferLength;
	(void)PreviousState;
	(void)ReturnLength;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
								  LPVOID TokenInformation, DWORD TokenInformationLength) {
	DEBUG_LOG("STUB: SetTokenInformation(%p, %u, %p, %u)\n", TokenHandle, TokenInformationClass, TokenInformation,
			  TokenInformationLength);
	(void)TokenInformationClass;
	(void)TokenInformation;
	(void)TokenInformationLength;
	auto data = handles::dataFromHandle(TokenHandle, false);
	if (data.type != handles::TYPE_TOKEN) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace advapi32
