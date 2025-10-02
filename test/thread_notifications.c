#include <windows.h>

static HMODULE g_module = NULL;
static volatile LONG g_threadAttachCount = 0;
static volatile LONG g_threadDetachCount = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)lpReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_module = hinstDLL;
        g_threadAttachCount = 0;
        g_threadDetachCount = 0;
        break;
    case DLL_THREAD_ATTACH:
        InterlockedIncrement(&g_threadAttachCount);
        break;
    case DLL_THREAD_DETACH:
        InterlockedIncrement(&g_threadDetachCount);
        break;
    case DLL_PROCESS_DETACH:
        g_module = NULL;
        break;
    default:
        break;
    }
    return TRUE;
}

__declspec(dllexport) LONG get_thread_attach_count(void) {
    return g_threadAttachCount;
}

__declspec(dllexport) LONG get_thread_detach_count(void) {
    return g_threadDetachCount;
}

__declspec(dllexport) void reset_thread_counts(void) {
    g_threadAttachCount = 0;
    g_threadDetachCount = 0;
}

__declspec(dllexport) BOOL disable_thread_notifications(void) {
    return DisableThreadLibraryCalls(g_module);
}
