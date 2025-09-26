#include <windows.h>

static int attached = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	(void) hinstDLL;
	(void) lpReserved;
	if (fdwReason == DLL_PROCESS_ATTACH) {
		attached = 1;
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
