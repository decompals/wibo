#include "processthreadsapi.h"
#include "common.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "processes.h"
#include "strutil.h"
#include "timeutil.h"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <limits>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/resource.h>
#include <sys/syscall.h>
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

thread_local ThreadObject *g_currentThreadObject = nullptr;

struct ThreadStartData {
	ThreadObject *obj;
	LPTHREAD_START_ROUTINE entry;
	void *userData;
};

void threadCleanup(void *param) {
	ThreadObject *obj = static_cast<ThreadObject *>(param);
	if (!obj) {
		return;
	}
	{
		std::lock_guard lk(obj->m);
		obj->signaled.store(true, std::memory_order_release);
		// Exit code set before pthread_exit
	}
	g_currentThreadObject = nullptr;
	wibo::notifyDllThreadDetach();
	wibo::setThreadTibForHost(nullptr);
	// TODO: mark mutexes owned by this thread as abandoned
	obj->cv.notify_all();
	detail::deref(obj);
}

void *threadTrampoline(void *param) {
	// We ref'd the ThreadObject when constructing ThreadStartData,
	// so we need to deref it when done. (Either normal exit or via pthread_cleanup)
	ThreadStartData *dataPtr = static_cast<ThreadStartData *>(param);
	ThreadStartData data = *dataPtr;
	delete dataPtr;

	g_currentThreadObject = data.obj;

	// Install TIB
	TIB *threadTib = nullptr;
	uint16_t previousFs = 0;
	uint16_t previousGs = 0;
	if (wibo::tibSelector) {
		asm volatile("mov %%fs, %0" : "=r"(previousFs));
		asm volatile("mov %%gs, %0" : "=r"(previousGs));
		threadTib = wibo::allocateTib();
		if (threadTib) {
			wibo::initializeTibStackInfo(threadTib);
			if (wibo::installTibForCurrentThread(threadTib)) {
				threadTib->hostFsSelector = previousFs;
				threadTib->hostGsSelector = previousGs;
				threadTib->hostSegmentsValid = 1;
				wibo::setThreadTibForHost(threadTib);
			} else {
				fprintf(stderr, "!!! Failed to install TIB for new thread\n");
				wibo::destroyTib(threadTib);
				threadTib = nullptr;
			}
		}
	}

	// Wait until resumed (if suspended at start)
	{
		std::unique_lock lk(data.obj->m);
		data.obj->tib = threadTib;
		if (data.obj->suspendCount) {
			DEBUG_LOG("Thread is suspended at start; waiting...\n");
			data.obj->cv.wait(lk, [&] { return data.obj->suspendCount == 0; });
		}
	}

	wibo::notifyDllThreadAttach();
	DEBUG_LOG("Calling thread entry %p with userData %p\n", data.entry, data.userData);
	DWORD result = 0;
	if (data.entry) {
		GUEST_CONTEXT_GUARD(threadTib);
		result = data.entry(data.userData);
	}
	DEBUG_LOG("Thread exiting with code %u\n", result);
	{
		std::lock_guard lk(data.obj->m);
		data.obj->exitCode = result;
	}
	threadCleanup(data.obj);
	return nullptr;
}

inline bool isPseudoCurrentThreadHandle(HANDLE h) {
	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(h);
	return rawHandle == kernel32::kPseudoCurrentThreadHandleValue;
}

} // namespace

namespace kernel32 {

BOOL WIN_FUNC IsProcessorFeaturePresent(DWORD ProcessorFeature) {
	HOST_CONTEXT_GUARD();
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

HANDLE WIN_FUNC GetCurrentProcess() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCurrentProcess() -> %p\n", reinterpret_cast<void *>(static_cast<uintptr_t>(-1)));
	return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1));
}

DWORD WIN_FUNC GetCurrentProcessId() {
	HOST_CONTEXT_GUARD();
	DWORD pid = static_cast<DWORD>(getpid());
	DEBUG_LOG("GetCurrentProcessId() -> %u\n", pid);
	return pid;
}

DWORD WIN_FUNC GetCurrentThreadId() {
	HOST_CONTEXT_GUARD();
	pthread_t thread = pthread_self();
	const auto threadId = static_cast<DWORD>(thread);
	DEBUG_LOG("GetCurrentThreadId() -> %u\n", threadId);
	return threadId;
}

HANDLE WIN_FUNC GetCurrentThread() {
	HOST_CONTEXT_GUARD();
	HANDLE pseudoHandle = reinterpret_cast<HANDLE>(kPseudoCurrentThreadHandleValue);
	DEBUG_LOG("GetCurrentThread() -> %p\n", pseudoHandle);
	return pseudoHandle;
}

BOOL WIN_FUNC GetProcessAffinityMask(HANDLE hProcess, PDWORD_PTR lpProcessAffinityMask,
									 PDWORD_PTR lpSystemAffinityMask) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetProcessAffinityMask(%p, %p, %p)\n", hProcess, lpProcessAffinityMask, lpSystemAffinityMask);
	if (!lpProcessAffinityMask || !lpSystemAffinityMask) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(hProcess);
	bool isPseudoHandle = rawHandle == 0 || rawHandle == kPseudoCurrentProcessHandleValue;
	if (!isPseudoHandle) {
		auto obj = wibo::handles().getAs<ProcessObject>(hProcess);
		if (!obj) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0;
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetProcessAffinityMask(%p, 0x%lx)\n", hProcess, static_cast<unsigned long>(dwProcessAffinityMask));
	if (dwProcessAffinityMask == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(hProcess);
	bool isPseudoHandle = rawHandle == 0 || rawHandle == kPseudoCurrentProcessHandleValue;
	if (!isPseudoHandle) {
		auto obj = wibo::handles().getAs<ProcessObject>(hProcess);
		if (!obj) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0;
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetThreadAffinityMask(%p, 0x%lx)\n", hThread, static_cast<unsigned long>(dwThreadAffinityMask));
	if (dwThreadAffinityMask == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	if (!isPseudoCurrentThreadHandle(hThread)) {
		auto obj = wibo::handles().getAs<ThreadObject>(hThread);
		if (!obj) {
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ExitProcess(%u)\n", uExitCode);
	exit(static_cast<int>(uExitCode));
}

BOOL WIN_FUNC TerminateProcess(HANDLE hProcess, UINT uExitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("TerminateProcess(%p, %u)\n", hProcess, uExitCode);
	if (hProcess == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1))) {
		exit(static_cast<int>(uExitCode));
	}
	auto process = wibo::handles().getAs<ProcessObject>(hProcess);
	if (!process) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (process->signaled.load(std::memory_order_acquire)) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	std::lock_guard lk(process->m);
	if (syscall(SYS_pidfd_send_signal, process->pidfd, SIGKILL, nullptr, 0) != 0) {
		int err = errno;
		DEBUG_LOG("TerminateProcess: pidfd_send_signal(%d) failed: %s\n", process->pidfd, strerror(err));
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
	process->exitCode = uExitCode;
	process->forcedExitCode = true;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetExitCodeProcess(%p, %p)\n", hProcess, lpExitCode);
	if (!lpExitCode) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto process = wibo::handles().getAs<ProcessObject>(hProcess);
	if (!process) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	DWORD exitCode = STILL_ACTIVE;
	if (process->signaled.load(std::memory_order_acquire)) {
		std::lock_guard lk(process->m);
		exitCode = process->exitCode;
	}
	*lpExitCode = exitCode;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC TlsAlloc() {
	HOST_CONTEXT_GUARD();
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
	HOST_CONTEXT_GUARD();
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
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("TlsGetValue(%u)\n", dwTlsIndex);
	if (dwTlsIndex >= kMaxTlsValues || !g_tlsSlotsUsed[dwTlsIndex]) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return g_tlsSlots[dwTlsIndex];
}

BOOL WIN_FUNC TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue) {
	HOST_CONTEXT_GUARD();
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ResumeThread(%p)\n", hThread);
	// TODO: behavior with current thread handle?
	auto obj = wibo::handles().getAs<ThreadObject>(hThread);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return static_cast<DWORD>(-1);
	}
	DWORD previous = 0;
	bool notify = false;
	{
		std::lock_guard lk(obj->m);
		previous = obj->suspendCount;
		if (obj->suspendCount > 0) {
			obj->suspendCount--;
			if (obj->suspendCount == 0) {
				notify = true;
			}
		}
	}
	if (notify) {
		obj->cv.notify_all();
	}
	wibo::lastError = ERROR_SUCCESS;
	return previous;
}

HRESULT WIN_FUNC SetThreadDescription(HANDLE hThread, LPCWSTR lpThreadDescription) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetThreadDescription(%p, %p)\n", hThread, lpThreadDescription);
	(void)hThread;
	(void)lpThreadDescription;
	return S_OK;
}

HANDLE WIN_FUNC CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
							 LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
							 LPDWORD lpThreadId) {
	HOST_CONTEXT_GUARD();
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

	Pin<ThreadObject> obj = make_pin<ThreadObject>(0); // tid set during pthread_create
	if ((dwCreationFlags & CREATE_SUSPENDED) != 0) {
		obj->suspendCount = 1;
	}
	detail::ref(obj.get()); // Increment ref for the new thread to adopt
	ThreadStartData *startData = new ThreadStartData{obj.get(), lpStartAddress, lpParameter};

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (dwStackSize != 0) {
#ifdef PTHREAD_STACK_MIN
		dwStackSize = std::max(dwStackSize, static_cast<SIZE_T>(PTHREAD_STACK_MIN));
#endif
		// TODO: should we just ignore this?
		pthread_attr_setstacksize(&attr, dwStackSize);
	}

	int rc = pthread_create(&obj->thread, &attr, threadTrampoline, startData);
	pthread_attr_destroy(&attr);
	if (rc != 0) {
		// Clean up
		delete startData;
		detail::deref(obj.get());
		wibo::lastError = wibo::winErrorFromErrno(rc);
		return INVALID_HANDLE_VALUE;
	}

	if (lpThreadId) {
		std::size_t hashed = std::hash<pthread_t>{}(obj->thread);
		*lpThreadId = static_cast<DWORD>(hashed & 0xffffffffu);
	}

	wibo::lastError = ERROR_SUCCESS;
	return wibo::handles().alloc(std::move(obj), 0 /* TODO */, 0);
}

[[noreturn]] void WIN_FUNC ExitThread(DWORD dwExitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ExitThread(%u)\n", dwExitCode);
	ThreadObject *obj = g_currentThreadObject;
	{
		std::lock_guard lk(obj->m);
		obj->exitCode = dwExitCode;
	}
	// Can't use pthread_cleanup_push/pop because it can't unwind the Windows stack
	// So call the cleanup function directly before pthread_exit
	threadCleanup(obj);
	pthread_exit(nullptr);
}

BOOL WIN_FUNC GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetExitCodeThread(%p, %p)\n", hThread, lpExitCode);
	if (!lpExitCode) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (isPseudoCurrentThreadHandle(hThread)) {
		*lpExitCode = STILL_ACTIVE;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	auto obj = wibo::handles().getAs<ThreadObject>(hThread);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	std::lock_guard lk(obj->m);
	*lpExitCode = obj->exitCode;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetThreadPriority(HANDLE hThread, int nPriority) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetThreadPriority(%p, %d)\n", hThread, nPriority);
	(void)hThread;
	(void)nPriority;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

int WIN_FUNC GetThreadPriority(HANDLE hThread) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetThreadPriority(%p)\n", hThread);
	(void)hThread;
	wibo::lastError = ERROR_SUCCESS;
	return 0;
}

DWORD WIN_FUNC GetPriorityClass(HANDLE hProcess) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetPriorityClass(%p)\n", hProcess);
	(void)hProcess;
	wibo::lastError = ERROR_SUCCESS;
	return NORMAL_PRIORITY_CLASS;
}

BOOL WIN_FUNC GetThreadTimes(HANDLE hThread, FILETIME *lpCreationTime, FILETIME *lpExitTime, FILETIME *lpKernelTime,
							 FILETIME *lpUserTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetThreadTimes(%p, %p, %p, %p, %p)\n", hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

	if (!lpKernelTime || !lpUserTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	bool isPseudoCurrentThread = reinterpret_cast<uintptr_t>(hThread) == kernel32::kPseudoCurrentThreadHandleValue ||
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

	struct rusage usage{};
	if (getrusage(RUSAGE_THREAD, &usage) == 0) {
		*lpKernelTime = fileTimeFromTimeval(usage.ru_stime);
		*lpUserTime = fileTimeFromTimeval(usage.ru_utime);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	struct timespec cpuTime{};
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpuTime) == 0) {
		*lpKernelTime = fileTimeFromDuration(0);
		*lpUserTime = fileTimeFromTimespec(cpuTime);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	kernel32::setLastErrorFromErrno();
	*lpKernelTime = fileTimeFromDuration(0);
	*lpUserTime = fileTimeFromDuration(0);
	return FALSE;
}

BOOL WIN_FUNC CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
							 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
							 LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
							 LPPROCESS_INFORMATION lpProcessInformation) {
	HOST_CONTEXT_GUARD();
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
		std::vector<std::string> arguments = wibo::splitCommandLine(commandLine.c_str());
		if (arguments.empty()) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return FALSE;
		}
		application = arguments.front();
	}

	auto resolved = wibo::resolveExecutable(application, useSearchPath);
	if (!resolved) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return FALSE;
	}

	Pin<ProcessObject> obj;
	int spawnResult = wibo::spawnWithCommandLine(*resolved, commandLine, obj);
	if (spawnResult != 0) {
		wibo::lastError = (spawnResult == ENOENT) ? ERROR_FILE_NOT_FOUND : ERROR_ACCESS_DENIED;
		return FALSE;
	}
	pid_t pid = obj->pid;

	if (lpProcessInformation) {
		lpProcessInformation->hProcess = wibo::handles().alloc(std::move(obj), 0 /* TODO: access */, 0);
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
	HOST_CONTEXT_GUARD();
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetStartupInfoA(%p)\n", lpStartupInfo);
	populateStartupInfo(lpStartupInfo);
}

void WIN_FUNC GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetStartupInfoW(%p)\n", lpStartupInfo);
	populateStartupInfo(lpStartupInfo);
}

BOOL WIN_FUNC SetThreadStackGuarantee(PULONG StackSizeInBytes) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetThreadStackGuarantee(%p)\n", StackSizeInBytes);
	(void)StackSizeInBytes;
	return TRUE;
}

} // namespace kernel32
