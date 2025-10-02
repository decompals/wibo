#pragma once

#include "common.h"
#include "securitybaseapi.h"

#include <string>

namespace advapi32 {

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

bool isLocalSystemSid(const Sid *sid);
bool writeLocalSystemSid(Sid *sid);
std::string normalizePrivilegeName(const std::string &name);
LUID lookupOrGeneratePrivilegeLuid(const std::string &normalizedName);
void releaseToken(void *tokenPtr);

} // namespace advapi32
