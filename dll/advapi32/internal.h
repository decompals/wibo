#pragma once

#include "common.h"
#include "handles.h"
#include "securitybaseapi.h"

constexpr DWORD SECURITY_LOCAL_SYSTEM_RID = 18;

struct TokenObject : ObjectBase {
	static constexpr ObjectType kType = ObjectType::Token;

	Pin<> obj;
	DWORD desiredAccess;

	explicit TokenObject(Pin<> obj, DWORD desiredAccess)
		: ObjectBase(kType), obj(std::move(obj)), desiredAccess(desiredAccess) {}
};

using SidIdentifierAuthority = SID_IDENTIFIER_AUTHORITY;

struct Sid {
	BYTE Revision;
	BYTE SubAuthorityCount;
	SidIdentifierAuthority IdentifierAuthority;
	DWORD SubAuthority[1];
};
