#include "kernel32.h"

#include "modules.h"

#include <cstring>

extern "C" {
void fast_kernel32_GetCurrentThreadId();
void fast_kernel32_GetLastError();
void fast_kernel32_SetLastError();
void fast_kernel32_EnterCriticalSection();
void fast_kernel32_LeaveCriticalSection();
}

namespace {

void *kernel32Thunk(const char *name) {
	// Served in guest mode by src/fast_thunks.S instead of the generated thunks.
	if (strcmp(name, "GetCurrentThreadId") == 0) {
		return reinterpret_cast<void *>(&fast_kernel32_GetCurrentThreadId);
	}
	if (strcmp(name, "GetLastError") == 0) {
		return reinterpret_cast<void *>(&fast_kernel32_GetLastError);
	}
	if (strcmp(name, "SetLastError") == 0) {
		return reinterpret_cast<void *>(&fast_kernel32_SetLastError);
	}
	if (strcmp(name, "EnterCriticalSection") == 0) {
		return reinterpret_cast<void *>(&fast_kernel32_EnterCriticalSection);
	}
	if (strcmp(name, "LeaveCriticalSection") == 0) {
		return reinterpret_cast<void *>(&fast_kernel32_LeaveCriticalSection);
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
	kernel32Thunk,
	nullptr,
};
