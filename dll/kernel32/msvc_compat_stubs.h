#pragma once
#include "types.h"

namespace kernel32 {

ULONGLONG WINAPI GetEnabledXStateFeatures();
BOOL WINAPI SetThreadPreferredUILanguages(DWORD dwFlags, void *langs, unsigned int *pnum);
BOOL WINAPI GetThreadPreferredUILanguages(DWORD dwFlags, unsigned int *pulNumLanguages, unsigned short *pwszBuf, unsigned int *pcchBuf);
BOOL WINAPI IsValidLocaleName(void *lpLocaleName);
VOID WINAPI InitializeSRWLock(void **SRWLock);
DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, int bAlertable);
DWORD WINAPI WaitForMultipleObjectsEx(DWORD nCount, const HANDLE *lpHandles, int bWaitAll, DWORD dwMilliseconds, int bAlertable);
int WINAPI CompareStringEx(void *lpLocaleName, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2, int cchCount2, void *lpVersionInformation, void *lpReserved, void *lParam);

} // namespace kernel32
