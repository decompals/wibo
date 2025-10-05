#include "debugapi.h"
#include "common.h"
#include "errors.h"

namespace kernel32 {

BOOL WIN_FUNC IsDebuggerPresent() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsDebuggerPresent()\n");
	wibo::lastError = ERROR_SUCCESS;
	return FALSE;
}

} // namespace kernel32
