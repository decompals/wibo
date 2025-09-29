#include <windows.h>

static int attached = 0;
static HMODULE observedMainModule = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	(void) hinstDLL;
	(void) lpReserved;
	if (fdwReason == DLL_PROCESS_ATTACH) {
		attached = 1;
		observedMainModule = GetModuleHandleW(NULL);
	} else if (fdwReason == DLL_PROCESS_DETACH) {
		attached = 2;
	}
	return TRUE;
}

__declspec(dllexport) int __stdcall add_numbers(int a, int b) {
	return a + b;
}

__declspec(dllexport) int __stdcall was_attached(void) {
	return attached;
}

__declspec(dllexport) HMODULE __stdcall observed_main_module(void) {
	return observedMainModule;
}
