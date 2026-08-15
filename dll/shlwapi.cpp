#include "shlwapi.h"

#include "common.h"
#include "context.h"
#include "kernel32/minwinbase.h"
#include "modules.h"

#include <cstring>

namespace shlwapi {

LPSTR WINAPI PathAddBackslashA(LPSTR pszPath) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("PathAddBackslashA(%s)\n", pszPath ? pszPath : "(null)");
	if (!pszPath) {
		return nullptr;
	}

	size_t length = std::strlen(pszPath);
	if (length > 0 && pszPath[length - 1] == '\\') {
		return pszPath + length;
	}

	if (length + 1 >= MAX_PATH) {
		return nullptr;
	}

	pszPath[length] = '\\';
	pszPath[length + 1] = '\0';
	return pszPath + length + 1;
}

} // namespace shlwapi

#include "shlwapi_trampolines.h"

extern const wibo::ModuleStub lib_shlwapi = {
	(const char *[]){
		"shlwapi",
		nullptr,
	},
	shlwapiThunkByName,
	nullptr,
};
