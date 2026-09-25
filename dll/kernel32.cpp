#include "kernel32.h"

#include "common.h"
#include "kernel32/guest_stubs.h"
#include "modules.h"

namespace {

void *resolveByName(const char *name) {
	if (!wibo::debugEnabled) {
		if (void *stub = wibo::guestStubs::resolveByName(name)) {
			return stub;
		}
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
