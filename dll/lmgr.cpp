#include "common.h"

namespace lmgr {
	int WIN_ENTRY lp_checkout(int a, int b, const char* c, const char* d, int e, const char* f, int* out) {
		DEBUG_LOG("lp_checkout %d %d %s %s %d %s\n", a, b, c, d, e, f);
		*out = 1234;
		return 0;
	}

	int WIN_ENTRY lp_checkin() {
		DEBUG_LOG("lp_checkin\n");
		return 0;
	}
}

static void *resolveByOrdinal(uint16_t ordinal) {
	switch (ordinal) {
	case 189:
		return (void*)lmgr::lp_checkin;
	case 190:
		return (void*)lmgr::lp_checkout;
	}
	return 0;
}

wibo::Module lib_lmgr = {
	(const char *[]){
		"lmgr11",
		"lmgr11.dll",
		"lmgr326b",
		"lmgr326b.dll",
		"lmgr8c",
		"lmgr8c.dll",
		nullptr,
	},
	nullptr,
	resolveByOrdinal,
};
