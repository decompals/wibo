#include "lmgr.h"

#include "common.h"
#include "context.h"
#include "modules.h"

namespace lmgr {

int CDECL lc_checkout() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lc_checkout()\n");
	return 0;
}

int CDECL lc_set_attr() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lc_set_attr()\n");
	return 0;
}

int CDECL lc_new_job() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lc_new_job()\n");
	return 0;
}

int CDECL lc_free_job() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lc_free_job()\n");
	return 0;
}

int CDECL lc_checkin() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("lc_checkin()\n");
	return 0;
}

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
	case 33:
		return (void *)thunk_lmgr_lc_checkin;
	case 34:
		return (void *)thunk_lmgr_lc_checkout;
	case 43:
		return (void *)thunk_lmgr_lc_free_job;
	case 61:
		return (void *)thunk_lmgr_lc_set_attr;
	case 189:
		return (void *)thunk_lmgr_lp_checkin;
	case 190:
		return (void *)thunk_lmgr_lp_checkout;
	case 249:
		return (void *)thunk_lmgr_lc_new_job;
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
