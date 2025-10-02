#include "processthreadsapi.h"
#include "common.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "processes.h"
#include "strutil.h"
#include "timeutil.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <limits>
#include <pthread.h>
#include <string>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

namespace {

using kernel32::ThreadObject;

constexpr DWORD kMaxTlsValues = 100;
bool g_tlsSlotsUsed[kMaxTlsValues] = {false};
LPVOID g_tlsSlots[kMaxTlsValues] = {nullptr};

DWORD_PTR g_processAffinityMask = 0;
bool g_processAffinityMaskInitialized = false;

const FILETIME kDefaultThreadFileTime = {static_cast<DWORD>(UNIX_TIME_ZERO & 0xFFFFFFFFULL),
										 static_cast<DWORD>(UNIX_TIME_ZERO >> 32)};

constexpr DWORD STARTF_USESHOWWINDOW = 0x00000001;
constexpr DWORD STARTF_USESTDHANDLES = 0x00000100;
constexpr WORD SW_SHOWNORMAL = 1;

struct ThreadStartData {
	LPTHREAD_START_ROUTINE startRoutine;
	void *parameter;
	ThreadObject *threadObject;
};

FILETIME fileTimeFromTimeval(const struct timeval &value) {
	uint64_t total = 0;
	if (value.tv_sec > 0 || value.tv_usec > 0) {
		total = static_cast<uint64_t>(value.tv_sec) * 10000000ULL + static_cast<uint64_t>(value.tv_usec) * 10ULL;
	}
	return fileTimeFromDuration(total);
}

FILETIME fileTimeFromTimespec(const struct timespec &value) {
	uint64_t total = 0;
	if (value.tv_sec > 0 || value.tv_nsec > 0) {
		total = static_cast<uint64_t>(value.tv_sec) * 10000000ULL + static_cast<uint64_t>(value.tv_nsec) / 100ULL;
	}
	return fileTimeFromDuration(total);
}

void destroyThreadObject(ThreadObject *obj) {
	if (!obj) {
		return;
	}
	pthread_cond_destroy(&obj->cond);
	pthread_mutex_destroy(&obj->mutex);
	delete obj;
}

DWORD_PTR computeSystemAffinityMask() {
	long reported = sysconf(_SC_NPROCESSORS_ONLN);
	if (reported <= 0) {
		reported = 1;
	}
	const auto bitCount = static_cast<unsigned int>(std::numeric_limits<DWORD_PTR>::digits);
	const auto usable = static_cast<unsigned int>(reported);
	if (usable >= bitCount) {
		return static_cast<DWORD_PTR>(~static_cast<DWORD_PTR>(0));
	}
	return (static_cast<DWORD_PTR>(1) << usable) - 1;
}

template <typename StartupInfo> void populateStartupInfo(StartupInfo *info) {
	if (!info) {
		return;
	}
	std::memset(info, 0, sizeof(StartupInfo));
	info->cb = sizeof(StartupInfo);
	info->dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	info->wShowWindow = SW_SHOWNORMAL;
	info->cbReserved2 = 0;
	info->lpReserved2 = nullptr;
	info->hStdInput = files::getStdHandle(STD_INPUT_HANDLE);
	info->hStdOutput = files::getStdHandle(STD_OUTPUT_HANDLE);
	info->hStdError = files::getStdHandle(STD_ERROR_HANDLE);
}

} // namespace

namespace kernel32 {

BOOL WIN_FUNC IsProcessorFeaturePresent(DWORD ProcessorFeature) {
	DEBUG_LOG("IsProcessorFeaturePresent(%u)\n", ProcessorFeature);
	if (ProcessorFeature == 0) { // PF_FLOATING_POINT_PRECISION_ERRATA
		return TRUE;
	}
	if (ProcessorFeature == 10) { // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
		return TRUE;
	}
	if (ProcessorFeature == 23) { // PF_FASTFAIL_AVAILABLE (__fastfail() supported)
		return TRUE;
	}
	DEBUG_LOG("  IsProcessorFeaturePresent: unknown feature %u, returning TRUE\n", ProcessorFeature);
	return TRUE;
}

thread_local ThreadObject *g_currentThreadObject = nullptr;

ThreadObject *ensureCurrentThreadObject() {
	ThreadObject *obj = g_currentThreadObject;
	if (obj) {
		return obj;
	}
	obj = new ThreadObject();
	obj->thread = pthread_self();
	obj->finished = false;
	obj->joined = false;
	obj->detached = true;
	obj->synthetic = false;
	obj->exitCode = STILL_ACTIVE;
	obj->refCount = 0;
	obj->suspendCount = 0;
	pthread_mutex_init(&obj->mutex, nullptr);
	pthread_cond_init(&obj->cond, nullptr);
	g_currentThreadObject = obj;
	return obj;
}

ThreadObject *threadObjectFromHandle(HANDLE hThread) {
	auto raw = reinterpret_cast<uintptr_t>(hThread);
	if (raw == kPseudoCurrentThreadHandleValue) {
		return ensureCurrentThreadObject();
	}
	if (raw == static_cast<uintptr_t>(-1) || raw == 0) {
		return nullptr;
	}
	auto data = handles::dataFromHandle(hThread, false);
	if (data.type != handles::TYPE_THREAD || data.ptr == nullptr) {
		return nullptr;
	}
	return reinterpret_cast<ThreadObject *>(data.ptr);
}

ThreadObject *retainThreadObject(ThreadObject *obj) {
	if (!obj) {
		return nullptr;
	}
	pthread_mutex_lock(&obj->mutex);
	obj->refCount++;
	pthread_mutex_unlock(&obj->mutex);
	return obj;
}

void releaseThreadObject(ThreadObject *obj) {
	if (!obj) {
		return;
	}
	pthread_t thread = 0;
	pthread_mutex_lock(&obj->mutex);
	obj->refCount--;
	bool shouldDelete = false;
	bool shouldDetach = false;
	bool finished = obj->finished;
	bool joined = obj->joined;
	bool detached = obj->detached;
	bool synthetic = obj->synthetic;
	thread = obj->thread;
	if (obj->refCount == 0) {
		if (finished || synthetic) {
			shouldDelete = true;
		} else if (!detached) {
			obj->detached = true;
			shouldDetach = true;
			detached = true;
		}
	}
	pthread_mutex_unlock(&obj->mutex);

	if (shouldDetach && !synthetic) {
		pthread_detach(thread);
	}

	if (shouldDelete) {
		if (!synthetic) {
			if (!joined && !detached) {
				pthread_join(thread, nullptr);
			}
		}
		destroyThreadObject(obj);
	}
}

static void *threadTrampoline(void *param) {
	ThreadStartData *data = static_cast<ThreadStartData *>(param);
	ThreadObject *obj = data->threadObject;
	LPTHREAD_START_ROUTINE startRoutine = data->startRoutine;
	void *userParam = data->parameter;
	delete data;

	uint16_t previousSegment = 0;
	bool tibInstalled = false;
	if (wibo::tibSelector) {
		asm volatile("mov %%fs, %0" : "=r"(previousSegment));
		asm volatile("movw %0, %%fs" : : "r"(wibo::tibSelector) : "memory");
		tibInstalled = true;
	}

	g_currentThreadObject = obj;
	pthread_mutex_lock(&obj->mutex);
	while (obj->suspendCount > 0) {
		pthread_cond_wait(&obj->cond, &obj->mutex);
	}
	pthread_mutex_unlock(&obj->mutex);
	DWORD result = startRoutine ? startRoutine(userParam) : 0;
	pthread_mutex_lock(&obj->mutex);
	obj->finished = true;
	obj->exitCode = result;
	pthread_cond_broadcast(&obj->cond);
	bool shouldDelete = (obj->refCount == 0);
	bool detached = obj->detached;
	pthread_mutex_unlock(&obj->mutex);
	g_currentThreadObject = nullptr;

	if (shouldDelete) {
		assert(detached && "ThreadObject must be detached when refCount reaches zero before completion");
		destroyThreadObject(obj);
	}

	if (tibInstalled) {
		asm volatile("movw %0, %%fs" : : "r"(previousSegment) : "memory");
	}
	return nullptr;
}

HANDLE WIN_FUNC GetCurrentProcess() {
	DEBUG_LOG("GetCurrentProcess() -> %p\n", reinterpret_cast<void *>(static_cast<uintptr_t>(-1)));
	return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1));
}

DWORD WIN_FUNC GetCurrentProcessId() {
	DWORD pid = static_cast<DWORD>(getpid());
	DEBUG_LOG("GetCurrentProcessId() -> %u\n", pid);
	return pid;
}

DWORD WIN_FUNC GetCurrentThreadId() {
	pthread_t thread = pthread_self();
	const auto threadId = static_cast<DWORD>(thread);
	DEBUG_LOG("GetCurrentThreadId() -> %u\n", threadId);
	return threadId;
}

HANDLE WIN_FUNC GetCurrentThread() {
	ThreadObject *obj = ensureCurrentThreadObject();
	(void)obj;
	HANDLE pseudoHandle = reinterpret_cast<HANDLE>(kPseudoCurrentThreadHandleValue);
	DEBUG_LOG("GetCurrentThread() -> %p\n", pseudoHandle);
	return pseudoHandle;
}

BOOL WIN_FUNC GetProcessAffinityMask(HANDLE hProcess, PDWORD_PTR lpProcessAffinityMask,
									 PDWORD_PTR lpSystemAffinityMask) {
	DEBUG_LOG("GetProcessAffinityMask(%p, %p, %p)\n", hProcess, lpProcessAffinityMask, lpSystemAffinityMask);
	if (!lpProcessAffinityMask || !lpSystemAffinityMask) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(hProcess);
	bool isPseudoHandle = rawHandle == static_cast<uintptr_t>(-1);
	if (!isPseudoHandle) {
		auto data = handles::dataFromHandle(hProcess, false);
		if (data.type != handles::TYPE_PROCESS || data.ptr == nullptr) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
	}

	DWORD_PTR systemMask = computeSystemAffinityMask();
	if (!g_processAffinityMaskInitialized) {
		g_processAffinityMask = systemMask;
		g_processAffinityMaskInitialized = true;
	}
	DWORD_PTR processMask = g_processAffinityMask & systemMask;
	if (processMask == 0) {
		processMask = systemMask == 0 ? 1 : systemMask;
	}

	*lpProcessAffinityMask = processMask;
	*lpSystemAffinityMask = systemMask == 0 ? 1 : systemMask;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR dwProcessAffinityMask) {
	DEBUG_LOG("SetProcessAffinityMask(%p, 0x%lx)\n", hProcess, static_cast<unsigned long>(dwProcessAffinityMask));
	if (dwProcessAffinityMask == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(hProcess);
	bool isPseudoHandle = rawHandle == static_cast<uintptr_t>(-1);
	if (!isPseudoHandle) {
		auto data = handles::dataFromHandle(hProcess, false);
		if (data.type != handles::TYPE_PROCESS) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
	}

	DWORD_PTR systemMask = computeSystemAffinityMask();
	if ((dwProcessAffinityMask & systemMask) == 0 || (dwProcessAffinityMask & ~systemMask) != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	g_processAffinityMask = dwProcessAffinityMask & systemMask;
	g_processAffinityMaskInitialized = true;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD_PTR WIN_FUNC SetThreadAffinityMask(HANDLE hThread, DWORD_PTR dwThreadAffinityMask) {
	DEBUG_LOG("SetThreadAffinityMask(%p, 0x%lx)\n", hThread, static_cast<unsigned long>(dwThreadAffinityMask));
	if (dwThreadAffinityMask == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	uintptr_t rawThreadHandle = reinterpret_cast<uintptr_t>(hThread);
	bool isPseudoHandle = rawThreadHandle == kPseudoCurrentThreadHandleValue || rawThreadHandle == 0 ||
						  rawThreadHandle == static_cast<uintptr_t>(-1);
	if (!isPseudoHandle) {
		auto data = handles::dataFromHandle(hThread, false);
		if (data.type != handles::TYPE_THREAD) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0;
		}
	}

	DWORD_PTR processMask = 0;
	DWORD_PTR systemMask = 0;
	if (!GetProcessAffinityMask(GetCurrentProcess(), &processMask, &systemMask)) {
		return 0;
	}
	if ((dwThreadAffinityMask & ~systemMask) != 0 || (dwThreadAffinityMask & processMask) == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	wibo::lastError = ERROR_SUCCESS;
	return processMask;
}

void WIN_FUNC ExitProcess(UINT uExitCode) {
	DEBUG_LOG("ExitProcess(%u)\n", uExitCode);
	std::exit(static_cast<int>(uExitCode));
}

BOOL WIN_FUNC TerminateProcess(HANDLE hProcess, UINT uExitCode) {
	DEBUG_LOG("TerminateProcess(%p, %u)\n", hProcess, uExitCode);
	if (hProcess == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1))) {
		ExitProcess(uExitCode);
	}
	auto data = handles::dataFromHandle(hProcess, false);
	if (data.type != handles::TYPE_PROCESS || data.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	auto *process = reinterpret_cast<processes::Process *>(data.ptr);
	if (kill(process->pid, SIGKILL) != 0) {
		int err = errno;
		DEBUG_LOG("TerminateProcess: kill(%d) failed: %s\n", process->pid, strerror(err));
		switch (err) {
		case ESRCH:
		case EPERM:
			wibo::lastError = ERROR_ACCESS_DENIED;
			break;
		default:
			wibo::lastError = ERROR_INVALID_PARAMETER;
			break;
		}
		return FALSE;
	}
	process->forcedExitCode = uExitCode;
	process->terminationRequested = true;
	process->exitCode = uExitCode;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
	DEBUG_LOG("GetExitCodeProcess(%p, %p)\n", hProcess, lpExitCode);
	if (!lpExitCode) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto *process = processes::processFromHandle(hProcess, false);
	if (!process) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	*lpExitCode = process->exitCode;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC TlsAlloc() {
	VERBOSE_LOG("TlsAlloc()\n");
	for (DWORD i = 0; i < kMaxTlsValues; ++i) {
		if (!g_tlsSlotsUsed[i]) {
			g_tlsSlotsUsed[i] = true;
			g_tlsSlots[i] = nullptr;
			wibo::lastError = ERROR_SUCCESS;
			return i;
		}
	}
	wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
	return TLS_OUT_OF_INDEXES;
}

BOOL WIN_FUNC TlsFree(DWORD dwTlsIndex) {
	VERBOSE_LOG("TlsFree(%u)\n", dwTlsIndex);
	if (dwTlsIndex >= kMaxTlsValues || !g_tlsSlotsUsed[dwTlsIndex]) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	g_tlsSlotsUsed[dwTlsIndex] = false;
	g_tlsSlots[dwTlsIndex] = nullptr;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

LPVOID WIN_FUNC TlsGetValue(DWORD dwTlsIndex) {
	VERBOSE_LOG("TlsGetValue(%u)\n", dwTlsIndex);
	if (dwTlsIndex >= kMaxTlsValues || !g_tlsSlotsUsed[dwTlsIndex]) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return g_tlsSlots[dwTlsIndex];
}

BOOL WIN_FUNC TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue) {
	VERBOSE_LOG("TlsSetValue(%u, %p)\n", dwTlsIndex, lpTlsValue);
	if (dwTlsIndex >= kMaxTlsValues || !g_tlsSlotsUsed[dwTlsIndex]) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	g_tlsSlots[dwTlsIndex] = lpTlsValue;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC ResumeThread(HANDLE hThread) {
	DEBUG_LOG("ResumeThread(%p)\n", hThread);
	ThreadObject *obj = threadObjectFromHandle(hThread);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return static_cast<DWORD>(-1);
	}
	pthread_mutex_lock(&obj->mutex);
	DWORD previous = obj->suspendCount;
	if (obj->suspendCount > 0) {
		obj->suspendCount--;
		if (obj->suspendCount == 0) {
			pthread_cond_broadcast(&obj->cond);
		}
	}
	pthread_mutex_unlock(&obj->mutex);
	wibo::lastError = ERROR_SUCCESS;
	return previous;
}

HRESULT WIN_FUNC SetThreadDescription(HANDLE hThread, LPCWSTR lpThreadDescription) {
	DEBUG_LOG("STUB: SetThreadDescription(%p, %p)\n", hThread, lpThreadDescription);
	(void)hThread;
	(void)lpThreadDescription;
	return S_OK;
}

HANDLE WIN_FUNC CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
							 LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
							 LPDWORD lpThreadId) {
	DEBUG_LOG("CreateThread(%p, %zu, %p, %p, %u, %p)\n", lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
			  dwCreationFlags, lpThreadId);
	(void)lpThreadAttributes;
	constexpr DWORD CREATE_SUSPENDED = 0x00000004;
	constexpr DWORD STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000;
	constexpr DWORD SUPPORTED_FLAGS = CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION;
	if ((dwCreationFlags & ~SUPPORTED_FLAGS) != 0) {
		DEBUG_LOG("CreateThread: unsupported creation flags 0x%x\n", dwCreationFlags);
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return nullptr;
	}
	bool startSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

	ThreadObject *obj = new ThreadObject();
	pthread_mutex_init(&obj->mutex, nullptr);
	pthread_cond_init(&obj->cond, nullptr);
	obj->finished = false;
	obj->joined = false;
	obj->detached = false;
	obj->exitCode = 0;
	obj->refCount = 1;
	obj->suspendCount = startSuspended ? 1u : 0u;
	obj->synthetic = false;

	ThreadStartData *startData = new ThreadStartData{lpStartAddress, lpParameter, obj};

	pthread_attr_t attr;
	pthread_attr_t *attrPtr = nullptr;
	if (dwStackSize != 0) {
		pthread_attr_init(&attr);
		size_t stackSize = dwStackSize;
#ifdef PTHREAD_STACK_MIN
		if (stackSize < static_cast<size_t>(PTHREAD_STACK_MIN)) {
			stackSize = PTHREAD_STACK_MIN;
		}
#endif
		if (pthread_attr_setstacksize(&attr, stackSize) == 0) {
			attrPtr = &attr;
		} else {
			pthread_attr_destroy(&attr);
		}
	}

	int rc = pthread_create(&obj->thread, attrPtr, threadTrampoline, startData);
	if (attrPtr) {
		pthread_attr_destroy(attrPtr);
	}
	if (rc != 0) {
		delete startData;
		destroyThreadObject(obj);
		errno = rc;
		setLastErrorFromErrno();
		return nullptr;
	}

	if (lpThreadId) {
		std::size_t hashed = std::hash<pthread_t>{}(obj->thread);
		*lpThreadId = static_cast<DWORD>(hashed & 0xffffffffu);
	}

	wibo::lastError = ERROR_SUCCESS;
	return handles::allocDataHandle({handles::TYPE_THREAD, obj, 0});
}

void WIN_FUNC ExitThread(DWORD dwExitCode) {
	DEBUG_LOG("ExitThread(%u)\n", dwExitCode);
	ThreadObject *obj = g_currentThreadObject;
	uint16_t previousSegment = 0;
	bool tibInstalled = false;
	if (wibo::tibSelector) {
		asm volatile("mov %%fs, %0" : "=r"(previousSegment));
		asm volatile("movw %0, %%fs" : : "r"(wibo::tibSelector) : "memory");
		tibInstalled = true;
	}
	if (obj) {
		pthread_mutex_lock(&obj->mutex);
		obj->finished = true;
		obj->exitCode = dwExitCode;
		pthread_cond_broadcast(&obj->cond);
		bool shouldDelete = (obj->refCount == 0);
		bool detached = obj->detached;
		pthread_mutex_unlock(&obj->mutex);
		g_currentThreadObject = nullptr;
		if (shouldDelete) {
			assert(detached && "ThreadObject must be detached when refCount reaches zero before completion");
			destroyThreadObject(obj);
		}
	}
	if (tibInstalled) {
		asm volatile("movw %0, %%fs" : : "r"(previousSegment) : "memory");
	}
	pthread_exit(nullptr);
}

BOOL WIN_FUNC GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
	DEBUG_LOG("GetExitCodeThread(%p, %p)\n", hThread, lpExitCode);
	if (!lpExitCode) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	ThreadObject *obj = threadObjectFromHandle(hThread);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	pthread_mutex_lock(&obj->mutex);
	DWORD code = obj->finished ? obj->exitCode : STILL_ACTIVE;
	pthread_mutex_unlock(&obj->mutex);
	*lpExitCode = code;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetThreadPriority(HANDLE hThread, int nPriority) {
	DEBUG_LOG("STUB: SetThreadPriority(%p, %d)\n", hThread, nPriority);
	(void)hThread;
	(void)nPriority;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

int WIN_FUNC GetThreadPriority(HANDLE hThread) {
	DEBUG_LOG("STUB: GetThreadPriority(%p)\n", hThread);
	(void)hThread;
	wibo::lastError = ERROR_SUCCESS;
	return 0;
}

DWORD WIN_FUNC GetPriorityClass(HANDLE hProcess) {
	DEBUG_LOG("GetPriorityClass(%p)\n", hProcess);
	(void)hProcess;
	wibo::lastError = ERROR_SUCCESS;
	return NORMAL_PRIORITY_CLASS;
}

BOOL WIN_FUNC GetThreadTimes(HANDLE hThread, FILETIME *lpCreationTime, FILETIME *lpExitTime, FILETIME *lpKernelTime,
							 FILETIME *lpUserTime) {
	DEBUG_LOG("GetThreadTimes(%p, %p, %p, %p, %p)\n", hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

	if (!lpKernelTime || !lpUserTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	bool isPseudoCurrentThread = reinterpret_cast<uintptr_t>(hThread) == kPseudoCurrentThreadHandleValue ||
								 hThread == nullptr || hThread == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1));
	if (!isPseudoCurrentThread) {
		DEBUG_LOG("GetThreadTimes: unsupported handle %p\n", hThread);
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	if (lpCreationTime) {
		*lpCreationTime = kDefaultThreadFileTime;
	}
	if (lpExitTime) {
		lpExitTime->dwLowDateTime = 0;
		lpExitTime->dwHighDateTime = 0;
	}

	struct rusage usage;
	if (getrusage(RUSAGE_THREAD, &usage) == 0) {
		*lpKernelTime = fileTimeFromTimeval(usage.ru_stime);
		*lpUserTime = fileTimeFromTimeval(usage.ru_utime);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	struct timespec cpuTime;
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpuTime) == 0) {
		*lpKernelTime = fileTimeFromDuration(0);
		*lpUserTime = fileTimeFromTimespec(cpuTime);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	setLastErrorFromErrno();
	*lpKernelTime = fileTimeFromDuration(0);
	*lpUserTime = fileTimeFromDuration(0);
	return FALSE;
}

BOOL WIN_FUNC CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
							 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
							 LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
							 LPPROCESS_INFORMATION lpProcessInformation) {
	DEBUG_LOG("CreateProcessA %s \"%s\" %p %p %d 0x%x %p %s %p %p\n", lpApplicationName ? lpApplicationName : "<null>",
			  lpCommandLine ? lpCommandLine : "<null>", lpProcessAttributes, lpThreadAttributes, bInheritHandles,
			  dwCreationFlags, lpEnvironment, lpCurrentDirectory ? lpCurrentDirectory : "<none>", lpStartupInfo,
			  lpProcessInformation);

	bool useSearchPath = lpApplicationName == nullptr;
	std::string application;
	std::string commandLine = lpCommandLine ? lpCommandLine : "";
	if (lpApplicationName) {
		application = lpApplicationName;
	} else {
		std::vector<std::string> arguments = processes::splitCommandLine(commandLine.c_str());
		if (arguments.empty()) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return FALSE;
		}
		application = arguments.front();
	}

	auto resolved = processes::resolveExecutable(application, useSearchPath);
	if (!resolved) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return FALSE;
	}

	pid_t pid = -1;
	int spawnResult = processes::spawnWithCommandLine(*resolved, commandLine, &pid);
	if (spawnResult != 0) {
		wibo::lastError = (spawnResult == ENOENT) ? ERROR_FILE_NOT_FOUND : ERROR_ACCESS_DENIED;
		return FALSE;
	}

	if (lpProcessInformation) {
		lpProcessInformation->hProcess = processes::allocProcessHandle(pid);
		lpProcessInformation->hThread = nullptr;
		lpProcessInformation->dwProcessId = static_cast<DWORD>(pid);
		lpProcessInformation->dwThreadId = 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	(void)lpProcessAttributes;
	(void)lpThreadAttributes;
	(void)bInheritHandles;
	(void)dwCreationFlags;
	(void)lpEnvironment;
	(void)lpCurrentDirectory;
	(void)lpStartupInfo;
	return TRUE;
}

BOOL WIN_FUNC CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
							 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
							 LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
							 LPPROCESS_INFORMATION lpProcessInformation) {
	std::string applicationUtf8;
	if (lpApplicationName) {
		applicationUtf8 = wideStringToString(lpApplicationName);
	}
	std::string commandUtf8;
	if (lpCommandLine) {
		commandUtf8 = wideStringToString(lpCommandLine);
	}
	std::string directoryUtf8;
	if (lpCurrentDirectory) {
		directoryUtf8 = wideStringToString(lpCurrentDirectory);
	}
	DEBUG_LOG("CreateProcessW %s \"%s\" %p %p %d 0x%x %p %s %p %p\n",
			  applicationUtf8.empty() ? "<null>" : applicationUtf8.c_str(),
			  commandUtf8.empty() ? "<null>" : commandUtf8.c_str(), lpProcessAttributes, lpThreadAttributes,
			  bInheritHandles, dwCreationFlags, lpEnvironment, directoryUtf8.empty() ? "<none>" : directoryUtf8.c_str(),
			  lpStartupInfo, lpProcessInformation);
	std::vector<char> commandBuffer;
	if (!commandUtf8.empty()) {
		commandBuffer.assign(commandUtf8.begin(), commandUtf8.end());
		commandBuffer.push_back('\0');
	}
	LPSTR commandPtr = commandBuffer.empty() ? nullptr : commandBuffer.data();
	LPCSTR applicationPtr = applicationUtf8.empty() ? nullptr : applicationUtf8.c_str();
	LPCSTR directoryPtr = directoryUtf8.empty() ? nullptr : directoryUtf8.c_str();
	return CreateProcessA(applicationPtr, commandPtr, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
						  dwCreationFlags, lpEnvironment, directoryPtr, nullptr /* TODO: lpStartupInfo */,
						  lpProcessInformation);
}

void WIN_FUNC GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo) {
	DEBUG_LOG("GetStartupInfoA(%p)\n", lpStartupInfo);
	populateStartupInfo(lpStartupInfo);
}

void WIN_FUNC GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo) {
	DEBUG_LOG("GetStartupInfoW(%p)\n", lpStartupInfo);
	populateStartupInfo(lpStartupInfo);
}

BOOL WIN_FUNC SetThreadStackGuarantee(PULONG StackSizeInBytes) {
	DEBUG_LOG("STUB: SetThreadStackGuarantee(%p)\n", StackSizeInBytes);
	(void)StackSizeInBytes;
	return TRUE;
}

} // namespace kernel32
