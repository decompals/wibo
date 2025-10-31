#include "vcruntime.h"

#include "common.h"
#include "context.h"
#include "modules.h"

#include <cstring>

namespace vcruntime {

PVOID CDECL memcpy(PVOID dest, LPCVOID src, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	return ::memcpy(dest, src, count);
}

PVOID CDECL memset(PVOID dest, int ch, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	return ::memset(dest, ch, count);
}

int CDECL memcmp(LPCVOID buf1, LPCVOID buf2, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	return ::memcmp(buf1, buf2, count);
}

PVOID CDECL memmove(PVOID dest, LPCVOID src, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	return ::memmove(dest, src, count);
}

} // namespace vcruntime

#include "vcruntime_trampolines.h"

extern const wibo::ModuleStub lib_vcruntime = {
	(const char *[]){
		"vcruntime140",
		nullptr,
	},
	vcruntimeThunkByName,
	nullptr,
};
