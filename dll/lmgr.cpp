#include "lmgr.h"

#include "common.h"
#include "context.h"
#include "modules.h"

namespace lmgr {

int CDECL lp_checkout(int a, int b, LPCSTR c, LPCSTR d, int e, LPCSTR f, int *out) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lp_checkout(%d, %d, %s, %s, %d, %s)\n", a, b, c, d, e, f);
	*out = 1234;
	return 0;
}

int CDECL lp_checkin() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lp_checkin()\n");
	return 0;
}

} // namespace lmgr

#include "lmgr_trampolines.h"

static void *resolveByOrdinal(uint16_t ordinal) {
	switch (ordinal) {
	case 189:
		return (void *)thunk_lmgr_lp_checkin;
	case 190:
		return (void *)thunk_lmgr_lp_checkout;
	}
	return 0;
}

extern const wibo::ModuleStub lib_lmgr = {
	(const char *[]){
		"lmgr11",
		"lmgr326b",
		"lmgr8c",
		nullptr,
	},
	nullptr,
	resolveByOrdinal,
};
