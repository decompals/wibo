#include "processthreadsapi.h"

#include "errors.h"
#include "handles.h"
#include "internal.h"

namespace advapi32 {

BOOL WIN_FUNC OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
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
	data.size = sizeof(TokenObject);
	*TokenHandle = handles::allocDataHandle(data);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace advapi32
