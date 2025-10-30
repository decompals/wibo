#include "debugapi.h"

#include "common.h"
#include "context.h"

namespace kernel32 {

BOOL WINAPI IsDebuggerPresent() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsDebuggerPresent()\n");
	return FALSE;
}

} // namespace kernel32
