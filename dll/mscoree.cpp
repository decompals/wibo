#include "common.h"

namespace mscoree {

void WIN_FUNC CorExitProcess(int exitCode) {
	DEBUG_LOG("CorExitProcess(%i)\n", exitCode);
	exit(exitCode);
}

} // namespace mscoree

static void *resolveByName(const char *name) {
	if (strcmp(name, "CorExitProcess") == 0)
		return (void *)mscoree::CorExitProcess;
	return nullptr;
}

wibo::Module lib_mscoree = {
	(const char *[]){
		"mscoree",
		nullptr,
	},
	resolveByName,
	nullptr,
};
