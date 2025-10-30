#include "common.h"
#include "context.h"
#include "kernel32/internal.h"
#include "modules.h"

#include <cstring>

namespace mscoree {

void WIN_FUNC CorExitProcess(int exitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CorExitProcess(%i)\n", exitCode);
	kernel32::exitInternal(exitCode);
}

} // namespace mscoree

static void *resolveByName(const char *name) {
	if (strcmp(name, "CorExitProcess") == 0)
		return (void *)mscoree::CorExitProcess;
	return nullptr;
}

extern const wibo::ModuleStub lib_mscoree = {
	(const char *[]){
		"mscoree",
		nullptr,
	},
	resolveByName,
	nullptr,
};
