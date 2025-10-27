#include <windows.h>

#ifndef TLS_RELOC_INITIAL_VALUE
#define TLS_RELOC_INITIAL_VALUE 0x2468ACEDu
#endif

__attribute__((section(".tls$AAA"), used)) static int g_tlsInitialValue = (int)TLS_RELOC_INITIAL_VALUE;
__attribute__((section(".tls$ZZZ"), used)) static const int g_tlsTerminator = 0;

static int g_tlsCallbackCount = 0;

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved) {
	(void)module;
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		++g_tlsCallbackCount;
	}
}

__attribute__((section(".CRT$XLB"), used)) static const PIMAGE_TLS_CALLBACK g_tlsCallback = tls_callback;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	(void)lpReserved;
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
	}
	return TRUE;
}

__declspec(dllexport) int __stdcall tls_get_template_value(void) { return g_tlsInitialValue; }

__declspec(dllexport) void *__stdcall tls_template_address(void) { return &g_tlsInitialValue; }

__declspec(dllexport) int __stdcall tls_callback_hits(void) { return g_tlsCallbackCount; }

extern DWORD _tls_index;
__declspec(dllexport) DWORD __stdcall tls_module_index(void) { return _tls_index; }
