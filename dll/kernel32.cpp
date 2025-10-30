#include "modules.h"

#include "kernel32_trampolines.h"

extern const wibo::ModuleStub lib_kernel32 = {
	(const char *[]){
		"kernel32",
		nullptr,
	},
	kernel32_trampoline_by_name,
	nullptr,
};
