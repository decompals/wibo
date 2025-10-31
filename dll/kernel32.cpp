#include "kernel32.h"

#include "modules.h"

extern const wibo::ModuleStub lib_kernel32 = {
	(const char *[]){
		"kernel32",
		nullptr,
	},
	kernel32ThunkByName,
	nullptr,
};
