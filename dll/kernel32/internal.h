#pragma once

#include "common.h"
#include "minwinbase.h"

#include <pthread.h>
#include <string>

namespace kernel32 {

struct ThreadObject {
	pthread_t thread{};
	bool finished = false;
	bool joined = false;
	bool detached = false;
	bool synthetic = false;
	DWORD exitCode = 0;
	int refCount = 1;
	pthread_mutex_t mutex{};
	pthread_cond_t cond{};
	unsigned int suspendCount = 0;
};

struct MutexObject {
	pthread_mutex_t mutex{};
	bool ownerValid = false;
	pthread_t owner = 0;
	unsigned int recursionCount = 0;
	std::u16string name;
	int refCount = 1;
};

struct EventObject {
	pthread_mutex_t mutex{};
	pthread_cond_t cond{};
	bool manualReset = false;
	bool signaled = false;
	std::u16string name;
	int refCount = 1;
};

struct SemaphoreObject {
	pthread_mutex_t mutex{};
	pthread_cond_t cond{};
	LONG count = 0;
	LONG maxCount = 0;
	std::u16string name;
	int refCount = 1;
};

inline constexpr uintptr_t kPseudoCurrentThreadHandleValue = static_cast<uintptr_t>(-2);

void releaseMutexObject(MutexObject *obj);
void releaseEventObject(EventObject *obj);
void releaseSemaphoreObject(SemaphoreObject *obj);
void resetOverlappedEvent(OVERLAPPED *ov);
void signalOverlappedEvent(OVERLAPPED *ov);
void tryMarkExecutable(void *mem);
void setLastErrorFromErrno();
bool closeFileMappingHandle(void *mappingPtr);
int64_t getFileSizeFromHandle(HANDLE hFile);
ThreadObject *ensureCurrentThreadObject();
ThreadObject *threadObjectFromHandle(HANDLE hThread);
ThreadObject *retainThreadObject(ThreadObject *obj);
void releaseThreadObject(ThreadObject *obj);

} // namespace kernel32
