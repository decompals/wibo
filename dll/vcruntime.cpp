#include "common.h"

namespace vcruntime {

void *WIN_ENTRY memcpy(void *dest, const void *src, size_t count) { return ::memcpy(dest, src, count); }

void *WIN_ENTRY memset(void *dest, int ch, size_t count) { return ::memset(dest, ch, count); }

int WIN_ENTRY memcmp(const void *buf1, const void *buf2, size_t count) { return ::memcmp(buf1, buf2, count); }

} // namespace vcruntime

static void *resolveByName(const char *name) {
	if (strcmp(name, "memcpy") == 0)
		return (void *)vcruntime::memcpy;
	if (strcmp(name, "memset") == 0)
		return (void *)vcruntime::memset;
	if (strcmp(name, "memcmp") == 0)
		return (void *)vcruntime::memcmp;
	return nullptr;
}

wibo::Module lib_vcruntime = {
	(const char *[]){
		"vcruntime140",
		"vcruntime140.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
