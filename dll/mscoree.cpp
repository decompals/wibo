#include "mscoree.h"

#include "common.h"
#include "context.h"
#include "kernel32/internal.h"
#include "modules.h"

namespace mscoree {

VOID WINAPI CorExitProcess(int exitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CorExitProcess(%i)\n", exitCode);
	kernel32::exitInternal(exitCode);
}

} // namespace mscoree

#include "mscoree_trampolines.h"

extern const wibo::ModuleStub lib_mscoree = {
	(const char *[]){
		"mscoree",
		nullptr,
	},
	mscoreeThunkByName,
	nullptr,
};
