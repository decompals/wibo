#pragma once

#include "common.h"

struct ACL {
	BYTE AclRevision;
	BYTE Sbz1;
	WORD AclSize;
	WORD AceCount;
	WORD Sbz2;
};

struct ACE_HEADER {
	BYTE AceType;
	BYTE AceFlags;
	WORD AceSize;
};

struct ACCESS_ALLOWED_ACE {
	ACE_HEADER Header;
	DWORD Mask;
	DWORD SidStart;
};

struct SID_IDENTIFIER_AUTHORITY {
	BYTE Value[6];
};

struct SECURITY_DESCRIPTOR {
	BYTE Revision;
	BYTE Sbz1;
	WORD Control;
	void *Owner;
	void *Group;
	ACL *Sacl;
	ACL *Dacl;
};

using PSECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR *;
using PACL = ACL *;
using PSID_IDENTIFIER_AUTHORITY = SID_IDENTIFIER_AUTHORITY *;
using SECURITY_INFORMATION = DWORD;

constexpr DWORD SECURITY_DESCRIPTOR_REVISION = 1;
constexpr WORD SE_DACL_PRESENT = 0x0004;
constexpr WORD SE_DACL_DEFAULTED = 0x0008;

constexpr BYTE ACL_REVISION1 = 1;
constexpr BYTE ACL_REVISION2 = 2;
constexpr BYTE ACL_REVISION3 = 3;
constexpr BYTE ACL_REVISION4 = 4;
constexpr BYTE ACL_REVISION = ACL_REVISION2;
constexpr BYTE ACL_REVISION_DS = ACL_REVISION4;
constexpr BYTE ACCESS_ALLOWED_ACE_TYPE = 0x00;
constexpr BYTE SID_MAX_SUB_AUTHORITIES = 15;

struct TOKEN_PRIVILEGES;
using PTOKEN_PRIVILEGES = TOKEN_PRIVILEGES *;

enum TOKEN_INFORMATION_CLASS : DWORD {
	TokenUser = 1,
	TokenGroups,
	TokenPrivileges,
	TokenOwner,
	TokenPrimaryGroup,
	TokenDefaultDacl,
	TokenSource,
	TokenType,
	TokenImpersonationLevel,
	TokenStatistics,
	TokenRestrictedSids,
	TokenSessionId,
	TokenGroupsAndPrivileges,
	TokenSessionReference,
	TokenSandBoxInert,
	TokenAuditPolicy,
	TokenOrigin,
	TokenElevationType,
	TokenLinkedToken,
	TokenElevation = 20,
};

namespace advapi32 {

BOOL WIN_FUNC InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision);
BOOL WIN_FUNC AddAccessAllowedAce(PACL pAcl, DWORD dwAceRevision, DWORD AccessMask, PSID pSid);
BOOL WIN_FUNC FindFirstFreeAce(PACL pAcl, LPVOID *pAce);
PSID_IDENTIFIER_AUTHORITY WIN_FUNC GetSidIdentifierAuthority(PSID pSid);
PUCHAR WIN_FUNC GetSidSubAuthorityCount(PSID pSid);
PDWORD WIN_FUNC GetSidSubAuthority(PSID pSid, DWORD nSubAuthority);
BOOL WIN_FUNC ImpersonateLoggedOnUser(HANDLE hToken);
BOOL WIN_FUNC DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, void *lpTokenAttributes,
							   DWORD ImpersonationLevel, DWORD TokenType, PHANDLE phNewToken);
BOOL WIN_FUNC CopySid(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);
BOOL WIN_FUNC GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl,
										LPBOOL lpbDaclDefaulted);
BOOL WIN_FUNC SetKernelObjectSecurity(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
									  PSECURITY_DESCRIPTOR SecurityDescriptor);
BOOL WIN_FUNC InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
BOOL WIN_FUNC SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl,
										BOOL bDaclDefaulted);
BOOL WIN_FUNC GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
								  LPVOID TokenInformation, DWORD TokenInformationLength, LPDWORD ReturnLength);
BOOL WIN_FUNC AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
									DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, LPDWORD ReturnLength);
BOOL WIN_FUNC SetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
								  LPVOID TokenInformation, DWORD TokenInformationLength);

} // namespace advapi32
