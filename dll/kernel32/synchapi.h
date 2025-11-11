#pragma once

#include "minwinbase.h"
#include "types.h"

constexpr DWORD WAIT_OBJECT_0 = 0x00000000;
constexpr DWORD WAIT_ABANDONED = 0x00000080;
constexpr DWORD WAIT_TIMEOUT = 0x00000102;
constexpr DWORD WAIT_FAILED = 0xFFFFFFFF;
constexpr DWORD INFINITE = 0xFFFFFFFF;
constexpr DWORD MAXIMUM_WAIT_OBJECTS = 64;

constexpr DWORD INIT_ONCE_CHECK_ONLY = 0x00000001UL;
constexpr DWORD INIT_ONCE_ASYNC = 0x00000002UL;
constexpr DWORD INIT_ONCE_INIT_FAILED = 0x00000004UL;
constexpr DWORD INIT_ONCE_CTX_RESERVED_BITS = 2;

constexpr DWORD RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO = 0x01000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN = 0x02000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_FLAG_STATIC_INIT = 0x04000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE = 0x08000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO = 0x10000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_ALL_FLAG_BITS = 0xff000000UL;
constexpr DWORD RTL_CRITICAL_SECTION_FLAG_RESERVED = 0xe0000000UL;

struct RTL_CRITICAL_SECTION;

struct RTL_CRITICAL_SECTION_DEBUG {
	WORD Type;
	WORD CreatorBackTraceIndex;
	GUEST_PTR CriticalSection;
	LIST_ENTRY ProcessLocksList;
	DWORD EntryCount;
	DWORD ContentionCount;
	DWORD Flags;
	WORD CreatorBackTraceIndexHigh;
	WORD SpareWORD;
	DWORD Spare[2];
};

struct RTL_CRITICAL_SECTION {
	GUEST_PTR DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;
	HANDLE LockSemaphore;
	ULONG_PTR SpinCount;
};

static_assert(sizeof(RTL_CRITICAL_SECTION) == 24);

using PRTL_CRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using LPCRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using PCRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using PRTL_CRITICAL_SECTION_DEBUG = RTL_CRITICAL_SECTION_DEBUG *;

union RTL_RUN_ONCE {
	GUEST_PTR Ptr;
};

using PRTL_RUN_ONCE = RTL_RUN_ONCE *;
using INIT_ONCE = RTL_RUN_ONCE;
using PINIT_ONCE = INIT_ONCE *;
using LPINIT_ONCE = INIT_ONCE *;

constexpr INIT_ONCE INIT_ONCE_STATIC_INIT{GUEST_NULL};

union RTL_SRWLOCK {
	ULONG Value;
};

using SRWLOCK = RTL_SRWLOCK;
using PSRWLOCK = SRWLOCK *;
using PRTL_SRWLOCK = SRWLOCK *;

constexpr SRWLOCK SRWLOCK_INIT{GUEST_NULL};

namespace kernel32 {

void WINAPI Sleep(DWORD dwMilliseconds);
HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
BOOL WINAPI ReleaseMutex(HANDLE hMutex);
HANDLE WINAPI CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
						   LPCSTR lpName);
HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
						   LPCWSTR lpName);
BOOL WINAPI SetEvent(HANDLE hEvent);
BOOL WINAPI ResetEvent(HANDLE hEvent);
HANDLE WINAPI CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
							   LPCSTR lpName);
HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
							   LPCWSTR lpName);
BOOL WINAPI ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount);
DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DWORD WINAPI WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
void WINAPI InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
BOOL WINAPI InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags);
BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
void WINAPI DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
void WINAPI EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
BOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
BOOL WINAPI InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, GUEST_PTR *lpContext);
BOOL WINAPI InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext);
void WINAPI AcquireSRWLockShared(PSRWLOCK SRWLock);
void WINAPI ReleaseSRWLockShared(PSRWLOCK SRWLock);
void WINAPI AcquireSRWLockExclusive(PSRWLOCK SRWLock);
void WINAPI ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
BOOLEAN WINAPI TryAcquireSRWLockExclusive(PSRWLOCK SRWLock);
BOOLEAN WINAPI TryAcquireSRWLockShared(PSRWLOCK SRWLock);

} // namespace kernel32
