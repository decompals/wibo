#pragma once

#include "common.h"

enum SID_NAME_USE : DWORD {
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

namespace advapi32 {

BOOL WIN_FUNC LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName,
								LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, SID_NAME_USE *peUse);
BOOL WIN_FUNC LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
BOOL WIN_FUNC LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
BOOL WIN_FUNC GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);
BOOL WIN_FUNC GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);

} // namespace advapi32
