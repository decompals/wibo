#include "common.h"

namespace user32 {
	int WIN_FUNC LoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax) {
		printf("LoadStringA %p %d %d\n", hInstance, uID, cchBufferMax);
		return 0;
	}
}

void *wibo::resolveUser32(const char *name) {
	if (strcmp(name, "LoadStringA") == 0) return (void *) user32::LoadStringA;
	return 0;
}
