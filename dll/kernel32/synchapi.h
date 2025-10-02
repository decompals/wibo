#pragma once

#include "common.h"
#include "minwinbase.h"

constexpr DWORD WAIT_OBJECT_0 = 0x00000000;
constexpr DWORD WAIT_ABANDONED = 0x00000080;
constexpr DWORD WAIT_TIMEOUT = 0x00000102;
constexpr DWORD WAIT_FAILED = 0xFFFFFFFF;
constexpr DWORD INFINITE = 0xFFFFFFFF;

constexpr DWORD INIT_ONCE_CHECK_ONLY = 0x00000001UL;
constexpr DWORD INIT_ONCE_ASYNC = 0x00000002UL;
constexpr DWORD INIT_ONCE_INIT_FAILED = 0x00000004UL;
constexpr DWORD INIT_ONCE_CTX_RESERVED_BITS = 2;

constexpr DWORD CRITICAL_SECTION_NO_DEBUG_INFO = 0x01000000UL;

struct LIST_ENTRY {
	LIST_ENTRY *Flink;
	LIST_ENTRY *Blink;
};

struct RTL_CRITICAL_SECTION;

struct RTL_CRITICAL_SECTION_DEBUG {
	WORD Type;
	WORD CreatorBackTraceIndex;
	RTL_CRITICAL_SECTION *CriticalSection;
	LIST_ENTRY ProcessLocksList;
	DWORD EntryCount;
	DWORD ContentionCount;
	DWORD Flags;
	WORD CreatorBackTraceIndexHigh;
	WORD SpareWORD;
	DWORD Spare[2];
};

struct RTL_CRITICAL_SECTION {
	RTL_CRITICAL_SECTION_DEBUG *DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;
	HANDLE LockSemaphore;
	ULONG_PTR SpinCount;
};

using PRTL_CRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using LPCRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using PCRITICAL_SECTION = RTL_CRITICAL_SECTION *;
using PRTL_CRITICAL_SECTION_DEBUG = RTL_CRITICAL_SECTION_DEBUG *;

union RTL_RUN_ONCE {
	PVOID Ptr;
};

using PRTL_RUN_ONCE = RTL_RUN_ONCE *;
using INIT_ONCE = RTL_RUN_ONCE;
using PINIT_ONCE = INIT_ONCE *;
using LPINIT_ONCE = INIT_ONCE *;

constexpr INIT_ONCE INIT_ONCE_STATIC_INIT{nullptr};

union RTL_SRWLOCK {
	PVOID Ptr;
};

using SRWLOCK = RTL_SRWLOCK;
using PSRWLOCK = SRWLOCK *;
using PRTL_SRWLOCK = SRWLOCK *;

constexpr SRWLOCK SRWLOCK_INIT{nullptr};

namespace kernel32 {

void WIN_FUNC Sleep(DWORD dwMilliseconds);
HANDLE WIN_FUNC CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE WIN_FUNC CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
BOOL WIN_FUNC ReleaseMutex(HANDLE hMutex);
HANDLE WIN_FUNC CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCSTR lpName);
HANDLE WIN_FUNC CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCWSTR lpName);
BOOL WIN_FUNC SetEvent(HANDLE hEvent);
BOOL WIN_FUNC ResetEvent(HANDLE hEvent);
HANDLE WIN_FUNC CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCSTR lpName);
HANDLE WIN_FUNC CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCWSTR lpName);
BOOL WIN_FUNC ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount);
DWORD WIN_FUNC WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
void WIN_FUNC InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
BOOL WIN_FUNC InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags);
BOOL WIN_FUNC InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
void WIN_FUNC DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
void WIN_FUNC EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
void WIN_FUNC LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
BOOL WIN_FUNC InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID *lpContext);
BOOL WIN_FUNC InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext);
void WIN_FUNC AcquireSRWLockShared(PSRWLOCK SRWLock);
void WIN_FUNC ReleaseSRWLockShared(PSRWLOCK SRWLock);
void WIN_FUNC AcquireSRWLockExclusive(PSRWLOCK SRWLock);
void WIN_FUNC ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
BOOLEAN WIN_FUNC TryAcquireSRWLockExclusive(PSRWLOCK SRWLock);

} // namespace kernel32
