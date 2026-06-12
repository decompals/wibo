#include "msvc_compat_stubs.h"
#include "common.h"
#include "context.h"
#include "winnls.h"
#include "synchapi.h"

namespace kernel32 {

ULONGLONG WINAPI GetEnabledXStateFeatures() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetEnabledXStateFeatures()\n");
	return 0;
}

BOOL WINAPI SetThreadPreferredUILanguages(DWORD dwFlags, void *langs, unsigned int *pnum) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetThreadPreferredUILanguages()\n");
	(void)dwFlags; (void)langs; if (pnum) *pnum = 0; return TRUE;
}

BOOL WINAPI GetThreadPreferredUILanguages(DWORD dwFlags, unsigned int *pulNumLanguages, unsigned short *pwszBuf, unsigned int *pcchBuf) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetThreadPreferredUILanguages()\n");
	(void)dwFlags;
	if (pulNumLanguages) *pulNumLanguages = 0;
	if (pcchBuf) {
		if (pwszBuf && *pcchBuf >= 2) { pwszBuf[0] = 0; pwszBuf[1] = 0; }
		*pcchBuf = 2;
	}
	return TRUE;
}

BOOL WINAPI IsValidLocaleName(void *lpLocaleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsValidLocaleName()\n");
	(void)lpLocaleName; return TRUE;
}

VOID WINAPI InitializeSRWLock(void **SRWLock) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: InitializeSRWLock()\n");
	if (SRWLock) *SRWLock = nullptr;
}

DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, int bAlertable) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: WaitForSingleObjectEx()\n");
	(void)bAlertable; return WaitForSingleObject(hHandle, dwMilliseconds);
}

DWORD WINAPI WaitForMultipleObjectsEx(DWORD nCount, const HANDLE *lpHandles, int bWaitAll, DWORD dwMilliseconds, int bAlertable) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: WaitForMultipleObjectsEx()\n");
	(void)bAlertable; return WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

int WINAPI CompareStringEx(void *lpLocaleName, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2, int cchCount2, void *lpVersionInformation, void *lpReserved, void *lParam) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CompareStringEx()\n");
	(void)lpLocaleName; (void)lpVersionInformation; (void)lpReserved; (void)lParam;
	return CompareStringW(0x0409, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
}

} // namespace kernel32
