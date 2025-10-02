#include "advapi32/processthreadsapi.h"
#include "advapi32/securitybaseapi.h"
#include "advapi32/winbase.h"
#include "advapi32/wincrypt.h"
#include "advapi32/winreg.h"
#include "common.h"

#include <cstring>

namespace {

void *resolveByName(const char *name) {
	// processthreadsapi.h
	if (strcmp(name, "OpenProcessToken") == 0)
		return (void *)advapi32::OpenProcessToken;

	// securitybaseapi.h
	if (strcmp(name, "InitializeAcl") == 0)
		return (void *)advapi32::InitializeAcl;
	if (strcmp(name, "AddAccessAllowedAce") == 0)
		return (void *)advapi32::AddAccessAllowedAce;
	if (strcmp(name, "FindFirstFreeAce") == 0)
		return (void *)advapi32::FindFirstFreeAce;
	if (strcmp(name, "GetSidIdentifierAuthority") == 0)
		return (void *)advapi32::GetSidIdentifierAuthority;
	if (strcmp(name, "GetSidSubAuthorityCount") == 0)
		return (void *)advapi32::GetSidSubAuthorityCount;
	if (strcmp(name, "GetSidSubAuthority") == 0)
		return (void *)advapi32::GetSidSubAuthority;
	if (strcmp(name, "ImpersonateLoggedOnUser") == 0)
		return (void *)advapi32::ImpersonateLoggedOnUser;
	if (strcmp(name, "DuplicateTokenEx") == 0)
		return (void *)advapi32::DuplicateTokenEx;
	if (strcmp(name, "CopySid") == 0)
		return (void *)advapi32::CopySid;
	if (strcmp(name, "GetSecurityDescriptorDacl") == 0)
		return (void *)advapi32::GetSecurityDescriptorDacl;
	if (strcmp(name, "SetKernelObjectSecurity") == 0)
		return (void *)advapi32::SetKernelObjectSecurity;
	if (strcmp(name, "InitializeSecurityDescriptor") == 0)
		return (void *)advapi32::InitializeSecurityDescriptor;
	if (strcmp(name, "SetSecurityDescriptorDacl") == 0)
		return (void *)advapi32::SetSecurityDescriptorDacl;
	if (strcmp(name, "GetTokenInformation") == 0)
		return (void *)advapi32::GetTokenInformation;
	if (strcmp(name, "AdjustTokenPrivileges") == 0)
		return (void *)advapi32::AdjustTokenPrivileges;
	if (strcmp(name, "SetTokenInformation") == 0)
		return (void *)advapi32::SetTokenInformation;

	// winbase.h
	if (strcmp(name, "LookupAccountSidW") == 0)
		return (void *)advapi32::LookupAccountSidW;
	if (strcmp(name, "LookupPrivilegeValueA") == 0)
		return (void *)advapi32::LookupPrivilegeValueA;
	if (strcmp(name, "LookupPrivilegeValueW") == 0)
		return (void *)advapi32::LookupPrivilegeValueW;
	if (strcmp(name, "GetUserNameA") == 0)
		return (void *)advapi32::GetUserNameA;
	if (strcmp(name, "GetUserNameW") == 0)
		return (void *)advapi32::GetUserNameW;

	// wincrypt.h
	if (strcmp(name, "CryptReleaseContext") == 0)
		return (void *)advapi32::CryptReleaseContext;
	if (strcmp(name, "CryptAcquireContextW") == 0)
		return (void *)advapi32::CryptAcquireContextW;
	if (strcmp(name, "CryptGenRandom") == 0)
		return (void *)advapi32::CryptGenRandom;
	if (strcmp(name, "CryptCreateHash") == 0)
		return (void *)advapi32::CryptCreateHash;
	if (strcmp(name, "CryptHashData") == 0)
		return (void *)advapi32::CryptHashData;
	if (strcmp(name, "CryptGetHashParam") == 0)
		return (void *)advapi32::CryptGetHashParam;
	if (strcmp(name, "CryptDestroyHash") == 0)
		return (void *)advapi32::CryptDestroyHash;

	// winreg.h
	if (strcmp(name, "RegCreateKeyExA") == 0)
		return (void *)advapi32::RegCreateKeyExA;
	if (strcmp(name, "RegCreateKeyExW") == 0)
		return (void *)advapi32::RegCreateKeyExW;
	if (strcmp(name, "RegOpenKeyExA") == 0)
		return (void *)advapi32::RegOpenKeyExA;
	if (strcmp(name, "RegOpenKeyExW") == 0)
		return (void *)advapi32::RegOpenKeyExW;
	if (strcmp(name, "RegQueryValueExA") == 0)
		return (void *)advapi32::RegQueryValueExA;
	if (strcmp(name, "RegQueryValueExW") == 0)
		return (void *)advapi32::RegQueryValueExW;
	if (strcmp(name, "RegEnumKeyExA") == 0)
		return (void *)advapi32::RegEnumKeyExA;
	if (strcmp(name, "RegEnumKeyExW") == 0)
		return (void *)advapi32::RegEnumKeyExW;
	if (strcmp(name, "RegCloseKey") == 0)
		return (void *)advapi32::RegCloseKey;

	return nullptr;
}

} // namespace

wibo::Module lib_advapi32 = {
	(const char *[]){
		"advapi32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
