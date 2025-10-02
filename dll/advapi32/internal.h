#pragma once

#include "common.h"
#include "securitybaseapi.h"

constexpr DWORD SECURITY_LOCAL_SYSTEM_RID = 18;

constexpr BYTE kNtAuthority[6] = {0, 0, 0, 0, 0, 5};

struct TokenObject {
	HANDLE processHandle;
	DWORD desiredAccess;
};

using SidIdentifierAuthority = SID_IDENTIFIER_AUTHORITY;

struct Sid {
	BYTE Revision;
	BYTE SubAuthorityCount;
	SidIdentifierAuthority IdentifierAuthority;
	DWORD SubAuthority[1];
};
