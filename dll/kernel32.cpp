#include "kernel32.h"

#include "modules.h"
#include "seh.h"

namespace {

void *resolveByName(const char *name) {
	if (void *entry = wibo::seh::guestExport(name)) {
		return entry;
	}
	return kernel32ThunkByName(name);
}

} // namespace

extern const wibo::ModuleStub lib_kernel32 = {
	(const char *[]){
		"kernel32",
		"kernelbase",
		nullptr,
	},
	resolveByName,
	nullptr,
};
