#include "test_assert.h"
#include <stdint.h>
#include <windows.h>

#ifndef TLS_RELOC_PREFERRED_BASE
#define TLS_RELOC_PREFERRED_BASE 0x30000000u
#endif

#ifndef TLS_RELOC_INITIAL_VALUE
#define TLS_RELOC_INITIAL_VALUE 0x2468ACEDu
#endif

typedef int(__stdcall *tls_get_template_value_fn)(void);
typedef void *(__stdcall *tls_template_address_fn)(void);
typedef int(__stdcall *tls_callback_hits_fn)(void);

static void *reserve_preferred_region(size_t size) {
	void *preferred = (void *)(uintptr_t)TLS_RELOC_PREFERRED_BASE;
	void *reservation = VirtualAlloc(preferred, size, MEM_RESERVE, PAGE_NOACCESS);
	return reservation;
}

int main(void) {
	const size_t reservationSize = 0x200000; // 2 MB
	void *preferred = (void *)(uintptr_t)TLS_RELOC_PREFERRED_BASE;
	void *reservation = reserve_preferred_region(reservationSize);
	TEST_CHECK_MSG(reservation == preferred, "VirtualAlloc(%p) failed: %lu", preferred,
				   (unsigned long)GetLastError());

	HMODULE mod = LoadLibraryA("tls_reloc.dll");
	TEST_CHECK_MSG(mod != NULL, "LoadLibraryA failed: %lu", (unsigned long)GetLastError());

	TEST_CHECK_MSG(VirtualFree(reservation, 0, MEM_RELEASE) != 0, "VirtualFree failed: %lu",
				   (unsigned long)GetLastError());

	TEST_CHECK((uintptr_t)mod != (uintptr_t)preferred);

	FARPROC rawGet = GetProcAddress(mod, "tls_get_template_value@0");
	FARPROC rawAddr = GetProcAddress(mod, "tls_template_address@0");
	FARPROC rawHits = GetProcAddress(mod, "tls_callback_hits@0");
	TEST_CHECK(rawGet != NULL);
	TEST_CHECK(rawAddr != NULL);
	TEST_CHECK(rawHits != NULL);

	tls_get_template_value_fn tls_get_template_value = (tls_get_template_value_fn)(uintptr_t)rawGet;
	tls_template_address_fn tls_template_address = (tls_template_address_fn)(uintptr_t)rawAddr;
	tls_callback_hits_fn tls_callback_hits = (tls_callback_hits_fn)(uintptr_t)rawHits;

	void *templateAddr = tls_template_address();
	TEST_CHECK(templateAddr != NULL);

	int initial = tls_get_template_value();
	TEST_CHECK_EQ(TLS_RELOC_INITIAL_VALUE, (unsigned int)initial);

	int hits = tls_callback_hits();
	TEST_CHECK_EQ(1, hits);

	TEST_CHECK(FreeLibrary(mod));

	return EXIT_SUCCESS;
}
