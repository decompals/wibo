#include "common.h"
#include "files.h"
#include "processes.h"
#include "handles.h"
#include "resources.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <cwctype>
#include <filesystem>
#include <fnmatch.h>
#include <initializer_list>
#include <string>
#include <strings.h>
#include "strutil.h"
#include <mimalloc.h>
#include <random>
#include <stdarg.h>
#include <system_error>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <spawn.h>
#include <unistd.h>
#include <vector>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <mutex>
#include <unordered_map>

namespace advapi32 {
	void releaseToken(void *tokenPtr);
}

namespace {
	struct MappingObject;
	struct ViewInfo {
		void *mapBase = nullptr;
		size_t mapLength = 0;
		MappingObject *owner = nullptr;
	};

	struct MappingObject {
		int fd = -1;
		size_t maxSize = 0;
		unsigned int protect = 0;
		bool anonymous = false;
		bool closed = false;
		size_t refCount = 0;
	};

	void closeMappingIfPossible(MappingObject *mapping);
	void tryReleaseMapping(MappingObject *mapping);
	std::unordered_map<void *, ViewInfo> g_viewInfo;

	void closeMappingIfPossible(MappingObject *mapping) {
		if (!mapping) {
			return;
		}
		if (mapping->fd != -1) {
			close(mapping->fd);
			mapping->fd = -1;
		}
		delete mapping;
	}

	void tryReleaseMapping(MappingObject *mapping) {
		if (!mapping) {
			return;
		}
		if (mapping->closed && mapping->refCount == 0) {
			closeMappingIfPossible(mapping);
		}
	}

	using DWORD_PTR = uintptr_t;

	constexpr WORD PROCESSOR_ARCHITECTURE_INTEL = 0;
	constexpr WORD PROCESSOR_ARCHITECTURE_ARM = 5;
	constexpr WORD PROCESSOR_ARCHITECTURE_IA64 = 6;
	constexpr WORD PROCESSOR_ARCHITECTURE_AMD64 = 9;
	constexpr WORD PROCESSOR_ARCHITECTURE_ARM64 = 12;
	constexpr WORD PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF;

	constexpr DWORD PROCESSOR_INTEL_386 = 386;
	constexpr DWORD PROCESSOR_INTEL_486 = 486;
	constexpr DWORD PROCESSOR_INTEL_PENTIUM = 586;
	constexpr DWORD PROCESSOR_INTEL_IA64 = 2200;
	constexpr DWORD PROCESSOR_AMD_X8664 = 8664;

	struct SYSTEM_INFO {
		union {
			DWORD dwOemId;
			struct {
				WORD wProcessorArchitecture;
				WORD wReserved;
			};
		};
		DWORD dwPageSize;
		LPVOID lpMinimumApplicationAddress;
		LPVOID lpMaximumApplicationAddress;
		DWORD_PTR dwActiveProcessorMask;
		DWORD dwNumberOfProcessors;
		DWORD dwProcessorType;
		DWORD dwAllocationGranularity;
		WORD wProcessorLevel;
		WORD wProcessorRevision;
	};
}

typedef union _RTL_RUN_ONCE {
	PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;
typedef PRTL_RUN_ONCE LPINIT_ONCE;

#define EXCEPTION_MAXIMUM_PARAMETERS 15
typedef struct _EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;
typedef void *PCONTEXT;
typedef struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(PEXCEPTION_POINTERS ExceptionInfo);

namespace kernel32 {
	static void *doAlloc(unsigned int dwBytes, bool zero) {
		if (dwBytes == 0)
			dwBytes = 1;
		void *ret = mi_malloc_aligned(dwBytes, 8);
		if (ret && zero) {
			memset(ret, 0, mi_usable_size(ret));
		}
		return ret;
	}

	static void *doRealloc(void *mem, unsigned int dwBytes, bool zero) {
		if (dwBytes == 0)
			dwBytes = 1;
		size_t oldSize = mi_usable_size(mem);
		void *ret = mi_realloc_aligned(mem, dwBytes, 8);
		size_t newSize = mi_usable_size(ret);
		if (ret && zero && newSize > oldSize) {
			memset((char*)ret + oldSize, 0, newSize - oldSize);
		}
		return ret;
	}

	struct MutexObject {
		pthread_mutex_t mutex;
		bool ownerValid = false;
		pthread_t owner = 0;
		unsigned int recursionCount = 0;
		std::u16string name;
		int refCount = 1;
	};

	static std::mutex mutexRegistryLock;
	static std::unordered_map<std::u16string, MutexObject *> namedMutexes;

	static std::u16string makeMutexName(LPCWSTR name) {
		if (!name) {
			return std::u16string();
		}
		size_t len = wstrlen(reinterpret_cast<const uint16_t *>(name));
		return std::u16string(reinterpret_cast<const char16_t *>(name), len);
	}

	static void releaseMutexObject(MutexObject *obj) {
		if (!obj) {
			return;
		}
		std::lock_guard<std::mutex> lock(mutexRegistryLock);
		obj->refCount--;
		if (obj->refCount == 0) {
			if (!obj->name.empty()) {
				auto it = namedMutexes.find(obj->name);
				if (it != namedMutexes.end() && it->second == obj) {
					namedMutexes.erase(it);
				}
			}
			pthread_mutex_destroy(&obj->mutex);
			delete obj;
		}
	}

	static int doCompareString(const std::string &a, const std::string &b, unsigned int dwCmpFlags) {
		for (size_t i = 0; ; i++) {
			if (i == a.size()) {
				if (i == b.size()) {
					return 2; // CSTR_EQUAL
				}
				return 1; // CSTR_LESS_THAN
			}
			if (i == b.size()) {
				return 3; // CSTR_GREATER_THAN
			}
			unsigned char c = a[i], d = b[i];
			if (dwCmpFlags & 1) { // NORM_IGNORECASE
				if ('a' <= c && c <= 'z') c -= 'a' - 'A';
				if ('a' <= d && d <= 'z') d -= 'a' - 'A';
			}
			if (c != d) {
				return c < d ? 1 : 3;
			}
		}
	}

	int64_t getFileSize(void* hFile) {
		FILE *fp = files::fpFromHandle(hFile);
		struct stat64 st;
		fflush(fp);
		if (fstat64(fileno(fp), &st) == -1 || !S_ISREG(st.st_mode)) {
			wibo::lastError = 2; // ERROR_FILE_NOT_FOUND (?)
			return -1; // INVALID_FILE_SIZE
		}
		return st.st_size;
	}

	void setLastErrorFromErrno() {
		switch (errno) {
		case 0:
			wibo::lastError = ERROR_SUCCESS;
			break;
		case EACCES:
			wibo::lastError = ERROR_ACCESS_DENIED;
			break;
		case EEXIST:
			wibo::lastError = ERROR_ALREADY_EXISTS;
			break;
		case ENOENT:
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			break;
		case ENOTDIR:
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			break;
		default:
			wibo::lastError = ERROR_NOT_SUPPORTED;
			break;
		}
	}

	uint32_t WIN_FUNC GetLastError() {
		DEBUG_LOG("GetLastError() -> %u\n", wibo::lastError);
		return wibo::lastError;
	}

	void WIN_FUNC SetLastError(unsigned int dwErrCode) {
		DEBUG_LOG("SetLastError(%u)\n", dwErrCode);
		wibo::lastError = dwErrCode;
	}

	BOOL WIN_FUNC IsBadReadPtr(const void *lp, uintptr_t ucb) {
		DEBUG_LOG("STUB: IsBadReadPtr(ptr=%p, size=%zu)\n", lp, static_cast<size_t>(ucb));
		if (!lp) {
			return TRUE;
		}
		return FALSE;
	}

	BOOL WIN_FUNC Wow64DisableWow64FsRedirection(void **OldValue) {
		DEBUG_LOG("Wow64DisableWow64FsRedirection\n");
		if (OldValue) {
			*OldValue = nullptr;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC Wow64RevertWow64FsRedirection(void *OldValue) {
		DEBUG_LOG("Wow64RevertWow64FsRedirection\n");
		(void) OldValue;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	void WIN_FUNC RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments) {
		DEBUG_LOG("RaiseException(code=0x%x, flags=0x%x, args=%u)\n", dwExceptionCode, dwExceptionFlags, nNumberOfArguments);
		(void)lpArguments;
		exit(static_cast<int>(dwExceptionCode));
	}

	PVOID WIN_FUNC AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
		DEBUG_LOG("STUB: AddVectoredExceptionHandler(%u, %p)\n", first, handler);
		return (PVOID)handler;
	}

	// @brief returns a pseudo handle to the current process
	void *WIN_FUNC GetCurrentProcess() {
		// pseudo handle is always returned, and is -1 (a special constant)
		return (void *) 0xFFFFFFFF;
	}

	// @brief DWORD (unsigned int) returns a process identifier of the calling process.
	unsigned int WIN_FUNC GetCurrentProcessId() {
		uint32_t pid = getpid();
		DEBUG_LOG("Current processID is: %d\n", pid);

		return pid;
	}

	unsigned int WIN_FUNC GetCurrentThreadId() {
		pthread_t thread_id;
		thread_id = pthread_self();
		DEBUG_LOG("Current thread ID is: %lu\n", thread_id);

		// Cast thread_id to unsigned int to fit a DWORD
		unsigned int u_thread_id = (unsigned int) thread_id;

		return u_thread_id;
	}

	void WIN_FUNC ExitProcess(unsigned int uExitCode) {
		DEBUG_LOG("ExitProcess %d\n", uExitCode);
		exit(uExitCode);
	}

	BOOL WIN_FUNC GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
		DEBUG_LOG("GetExitCodeProcess\n");

		processes::Process* process = processes::processFromHandle(hProcess, false);
		*lpExitCode = process->exitCode;
		return 1; // success in retrieval
	}

	BOOL WIN_FUNC DisableThreadLibraryCalls(HMODULE hLibModule) {
		DEBUG_LOG("DisableThreadLibraryCalls(%p)\n", hLibModule);
		(void)hLibModule;
		return TRUE;
	}

	void WIN_FUNC GetSystemInfo(SYSTEM_INFO *lpSystemInfo) {
		DEBUG_LOG("GetSystemInfo\n");
		if (!lpSystemInfo) {
			return;
		}

		std::memset(lpSystemInfo, 0, sizeof(*lpSystemInfo));

		lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
		lpSystemInfo->wReserved = 0;
		lpSystemInfo->dwOemId = lpSystemInfo->wProcessorArchitecture;
		lpSystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
		lpSystemInfo->wProcessorLevel = 6; // Pentium
		lpSystemInfo->wProcessorRevision = 0;

		long pageSize = sysconf(_SC_PAGESIZE);
		if (pageSize <= 0) {
			pageSize = 4096;
		}
		lpSystemInfo->dwPageSize = static_cast<DWORD>(pageSize);

		lpSystemInfo->lpMinimumApplicationAddress = reinterpret_cast<LPVOID>(0x00010000);
		if (sizeof(void *) == 4) {
			lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x7FFEFFFF);
		} else {
			lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x00007FFFFFFEFFFFull);
		}

		unsigned int cpuCount = 1;
		long reported = sysconf(_SC_NPROCESSORS_ONLN);
		if (reported > 0) {
			cpuCount = static_cast<unsigned int>(reported);
		}
		lpSystemInfo->dwNumberOfProcessors = cpuCount;

		unsigned int maskWidth = static_cast<unsigned int>(sizeof(DWORD_PTR) * 8);
		DWORD_PTR mask;
		if (cpuCount >= maskWidth) {
			mask = static_cast<DWORD_PTR>(~static_cast<DWORD_PTR>(0));
		} else {
			mask = (static_cast<DWORD_PTR>(1) << cpuCount) - 1;
		}
		if (mask == 0) {
			mask = 1;
		}
		lpSystemInfo->dwActiveProcessorMask = mask;

		lpSystemInfo->dwAllocationGranularity = 0x10000;
	}

	struct PROCESS_INFORMATION {
		HANDLE hProcess;
		HANDLE hThread;
		DWORD  dwProcessId;
		DWORD  dwThreadId;
	};


	BOOL WIN_FUNC CreateProcessA(
		LPCSTR lpApplicationName,
		LPSTR lpCommandLine,
		void *lpProcessAttributes,
		void *lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCSTR lpCurrentDirectory,
		void *lpStartupInfo,
		PROCESS_INFORMATION *lpProcessInformation
	) {
		DEBUG_LOG("CreateProcessA %s \"%s\" %p %p %d 0x%x %p %s %p %p\n",
			lpApplicationName ? lpApplicationName : "<null>",
			lpCommandLine ? lpCommandLine : "<null>",
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory ? lpCurrentDirectory : "<none>",
			lpStartupInfo,
			lpProcessInformation
		);

		std::string application = lpApplicationName ? lpApplicationName : "";
		std::vector<std::string> arguments = processes::splitCommandLine(lpCommandLine);
		if (application.empty()) {
			if (arguments.empty()) {
				wibo::lastError = ERROR_FILE_NOT_FOUND;
				return 0;
			}
			application = arguments.front();
		}
		if (arguments.empty()) {
			arguments.push_back(application);
		}

		auto resolved = processes::resolveExecutable(application, true);
		if (!resolved) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return 0;
		}

		pid_t pid = -1;
		int spawnResult = processes::spawnViaWibo(*resolved, arguments, &pid);
		if (spawnResult != 0) {
			wibo::lastError = (spawnResult == ENOENT) ? ERROR_FILE_NOT_FOUND : ERROR_ACCESS_DENIED;
			return 0;
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
		return 1;
	}

	BOOL WIN_FUNC CreateProcessW(
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		void *lpProcessAttributes,
		void *lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		void *lpStartupInfo,
		PROCESS_INFORMATION *lpProcessInformation
	) {
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
			commandUtf8.empty() ? "<null>" : commandUtf8.c_str(),
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			directoryUtf8.empty() ? "<none>" : directoryUtf8.c_str(),
			lpStartupInfo,
			lpProcessInformation
		);
		std::vector<char> commandBuffer;
		if (!commandUtf8.empty()) {
			commandBuffer.assign(commandUtf8.begin(), commandUtf8.end());
			commandBuffer.push_back('\0');
		}
		LPSTR commandPtr = commandBuffer.empty() ? nullptr : commandBuffer.data();
		LPCSTR applicationPtr = applicationUtf8.empty() ? nullptr : applicationUtf8.c_str();
		LPCSTR directoryPtr = directoryUtf8.empty() ? nullptr : directoryUtf8.c_str();
		return CreateProcessA(
			applicationPtr,
			commandPtr,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			directoryPtr,
			lpStartupInfo,
			lpProcessInformation
		);
	}

	unsigned int WIN_FUNC WaitForSingleObject(void *hHandle, unsigned int dwMilliseconds) {
		DEBUG_LOG("WaitForSingleObject (%u)\n", dwMilliseconds);
		handles::Data data = handles::dataFromHandle(hHandle, false);
		switch (data.type) {
		case handles::TYPE_PROCESS: {
			// TODO: wait for less than forever
			assert(dwMilliseconds == 0xffffffff);
			processes::Process *process = reinterpret_cast<processes::Process *>(data.ptr);
			int status;
			waitpid(process->pid, &status, 0);
			if (WIFEXITED(status)) {
				process->exitCode = WEXITSTATUS(status);
			} else {
				DEBUG_LOG("WaitForSingleObject: Child process exited abnormally - returning exit code 1.\n");
				process->exitCode = 1;
			}
			wibo::lastError = ERROR_SUCCESS;
			return 0;
		}
		case handles::TYPE_MUTEX: {
			MutexObject *obj = reinterpret_cast<MutexObject *>(data.ptr);
			if (dwMilliseconds != 0xffffffff) {
				DEBUG_LOG("WaitForSingleObject: timeout for mutex not supported\n");
				wibo::lastError = ERROR_NOT_SUPPORTED;
				return 0xFFFFFFFF;
			}
			pthread_mutex_lock(&obj->mutex);
			pthread_t self = pthread_self();
			if (obj->ownerValid && pthread_equal(obj->owner, self)) {
				obj->recursionCount++;
			} else {
				obj->owner = self;
				obj->ownerValid = true;
				obj->recursionCount = 1;
			}
			wibo::lastError = ERROR_SUCCESS;
			return 0;
		}
		default:
			DEBUG_LOG("WaitForSingleObject: unsupported handle type %d\n", data.type);
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0xFFFFFFFF;
		}
	}

	int WIN_FUNC GetSystemDefaultLangID() {
		DEBUG_LOG("STUB GetSystemDefaultLangID\n");
		return 0;
	}

	struct LIST_ENTRY;
	struct LIST_ENTRY {
		LIST_ENTRY *Flink;
		LIST_ENTRY *Blink;
	};

	struct CRITICAL_SECTION_DEBUG;
	struct CRITICAL_SECTION {
		CRITICAL_SECTION_DEBUG *DebugInfo;
		unsigned int LockCount;
		unsigned int RecursionCount;
		void *OwningThread;
		void *LockSemaphore;
		unsigned int SpinCount;
	};

	struct CRITICAL_SECTION_DEBUG {
		int Type;
		int CreatorBackTraceIndex;
		CRITICAL_SECTION *CriticalSection;
		LIST_ENTRY ProcessLocksList;
		unsigned int EntryCount;
		unsigned int ContentionCount;
		unsigned int Flags;
		int CreatorBackTraceIndexHigh;
		int SpareUSHORT;
	};

	void WIN_FUNC InitializeCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC InitializeCriticalSectionEx(CRITICAL_SECTION *param) {
		// DEBUG_LOG("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC DeleteCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("DeleteCriticalSection(...)\n");
	}
	void WIN_FUNC EnterCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("EnterCriticalSection(...)\n");
	}
	void WIN_FUNC LeaveCriticalSection(CRITICAL_SECTION *param) {
		// DEBUG_LOG("LeaveCriticalSection(...)\n");
	}

	unsigned int WIN_FUNC InitializeCriticalSectionAndSpinCount(CRITICAL_SECTION *lpCriticalSection, unsigned int dwSpinCount) {
		DEBUG_LOG("InitializeCriticalSectionAndSpinCount (%i)\n", dwSpinCount);
		// can we get away with doing nothing...?
		memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
		lpCriticalSection->SpinCount = dwSpinCount;

		return 1;
	}

	int WIN_FUNC InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID* lpContext) {
		DEBUG_LOG("STUB: InitOnceBeginInitialize\n");
		if (fPending != nullptr) {
			*fPending = TRUE;
		}
		return 1;
	}

	BOOL WIN_FUNC InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext) {
		DEBUG_LOG("STUB: InitOnceComplete\n");
		return TRUE;
	}

	void WIN_FUNC AcquireSRWLockShared(void *SRWLock) { DEBUG_LOG("STUB: AcquireSRWLockShared(%p)\n", SRWLock); }

	void WIN_FUNC ReleaseSRWLockShared(void *SRWLock) { DEBUG_LOG("STUB: ReleaseSRWLockShared(%p)\n", SRWLock); }

	void WIN_FUNC AcquireSRWLockExclusive(void *SRWLock) { DEBUG_LOG("STUB: AcquireSRWLockExclusive(%p)\n", SRWLock); }

	void WIN_FUNC ReleaseSRWLockExclusive(void *SRWLock) { DEBUG_LOG("STUB: ReleaseSRWLockExclusive(%p)\n", SRWLock); }

	int WIN_FUNC TryAcquireSRWLockExclusive(void *SRWLock) {
		DEBUG_LOG("STUB: TryAcquireSRWLockExclusive(%p)\n", SRWLock);
		return 1;
	}

	/*
	 * TLS (Thread-Local Storage)
	 */
	enum { MAX_TLS_VALUES = 100 };
	static bool tlsValuesUsed[MAX_TLS_VALUES] = { false };
	static void *tlsValues[MAX_TLS_VALUES];
	unsigned int WIN_FUNC TlsAlloc() {
		DEBUG_LOG("TlsAlloc()\n");
		for (size_t i = 0; i < MAX_TLS_VALUES; i++) {
			if (tlsValuesUsed[i] == false) {
				tlsValuesUsed[i] = true;
				tlsValues[i] = 0;
				DEBUG_LOG("...returning %d\n", i);
				return i;
			}
		}
		DEBUG_LOG("...returning nothing\n");
		wibo::lastError = 1;
		return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
	}

	unsigned int WIN_FUNC TlsFree(unsigned int dwTlsIndex) {
		DEBUG_LOG("TlsFree(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValuesUsed[dwTlsIndex] = false;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	void *WIN_FUNC TlsGetValue(unsigned int dwTlsIndex) {
		// DEBUG_LOG("TlsGetValue(%u)", dwTlsIndex);
		void *result = nullptr;
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			result = tlsValues[dwTlsIndex];
			// See https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-TlsGetValue#return-value
			wibo::lastError = ERROR_SUCCESS;
		} else {
			wibo::lastError = 1;
		}
		// DEBUG_LOG(" -> %p\n", result);
		return result;
	}

	unsigned int WIN_FUNC TlsSetValue(unsigned int dwTlsIndex, void *lpTlsValue) {
		// DEBUG_LOG("TlsSetValue(%u, %p)\n", dwTlsIndex, lpTlsValue);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValues[dwTlsIndex] = lpTlsValue;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	/*
	 * Memory
	 */
	void *WIN_FUNC GlobalAlloc(uint32_t uFlags, size_t dwBytes) {
		// DEBUG_LOG("GlobalAlloc(flags=%x, size=%x)\n", uFlags, dwBytes);
		if (uFlags & 2) {
			// GMEM_MOVEABLE - not implemented rn
			assert(0);
			return 0;
		} else {
			// GMEM_FIXED - this is simpler
			bool zero = uFlags & 0x40; // GMEM_ZEROINT
			return doAlloc(dwBytes, zero);
		}
	}
	void *WIN_FUNC GlobalFree(void *hMem) {
		free(hMem);
		return 0;
	}

	void *WIN_FUNC GlobalReAlloc(void *hMem, size_t dwBytes, uint32_t uFlags) {
		if (uFlags & 0x80) { // GMEM_MODIFY
			assert(0);
		} else {
			bool zero = uFlags & 0x40; // GMEM_ZEROINT
			return doRealloc(hMem, dwBytes, zero);
		}
	}

	unsigned int WIN_FUNC GlobalFlags(void *hMem) {
		return 0;
	}

	/*
	 * Environment
	 */
	LPSTR WIN_FUNC GetCommandLineA() {
		DEBUG_LOG("GetCommandLineA\n");
		return wibo::commandLine;
	}

	LPWSTR WIN_FUNC GetCommandLineW() {
		DEBUG_LOG("GetCommandLineW -> \n");
		return wibo::commandLineW.data();
	}

	char *WIN_FUNC GetEnvironmentStrings() {
		DEBUG_LOG("GetEnvironmentStrings\n");
		// Step 1, figure out the size of the buffer we need.
		size_t bufSize = 0;
		char **work = environ;

		while (*work) {
			bufSize += strlen(*work) + 1;
			work++;
		}
		bufSize++;

		// Step 2, actually build that buffer
		char *buffer = (char *) mi_malloc(bufSize);
		char *ptr = buffer;
		work = environ;

		while (*work) {
			size_t strSize = strlen(*work);
			memcpy(ptr, *work, strSize);
			ptr[strSize] = 0;
			ptr += strSize + 1;
			work++;
		}
		*ptr = 0; // an extra null at the end

		return buffer;
	}

	uint16_t* WIN_FUNC GetEnvironmentStringsW() {
		DEBUG_LOG("GetEnvironmentStringsW\n");
		// Step 1, figure out the size of the buffer we need.
		size_t bufSizeW = 0;
		char **work = environ;

		while (*work) {
			// "hello|" -> " h e l l o|"
			bufSizeW += strlen(*work) + 1;
			work++;
		}
		bufSizeW++;

		// Step 2, actually build that buffer
		uint16_t *buffer = (uint16_t *) mi_malloc(bufSizeW * 2);
		uint16_t *ptr = buffer;
		work = environ;

		while (*work) {
			size_t strSize = strlen(*work);
			for (size_t i = 0; i < strSize; i++) {
				*ptr++ = (*work)[i] & 0xFF;
			}
			*ptr++ = 0; // NUL terminate
			work++;
		}
		*ptr = 0; // an extra null at the end

		return buffer;
	}

	void WIN_FUNC FreeEnvironmentStringsA(char *buffer) {
		DEBUG_LOG("FreeEnvironmentStringsA\n");
		free(buffer);
	}

	/*
	 * I/O
	 */
	void *WIN_FUNC GetStdHandle(uint32_t nStdHandle) {
		DEBUG_LOG("GetStdHandle %d\n", nStdHandle);
		return files::getStdHandle(nStdHandle);
	}

	unsigned int WIN_FUNC SetStdHandle(uint32_t nStdHandle, void *hHandle) {
		DEBUG_LOG("SetStdHandle %d %p\n", nStdHandle, hHandle);
		return files::setStdHandle(nStdHandle, hHandle);
	}

	unsigned int WIN_FUNC DuplicateHandle(void *hSourceProcessHandle, void *hSourceHandle, void *hTargetProcessHandle, void **lpTargetHandle, unsigned int dwDesiredAccess, unsigned int bInheritHandle, unsigned int dwOptions) {
		DEBUG_LOG("DuplicateHandle(source=%p)\n", hSourceHandle);
		FILE *fp = files::fpFromHandle(hSourceHandle);
		if (fp == stdin || fp == stdout || fp == stderr) {
			// we never close standard handles so they are fine to duplicate
			void *handle = files::allocFpHandle(fp);
			DEBUG_LOG("-> %p\n", handle);
			*lpTargetHandle = handle;
			return 1;
		}
		// other handles are more problematic; fail for now
		printf("failed to duplicate handle\n");
		assert(0);
	}

	BOOL WIN_FUNC CloseHandle(HANDLE hObject) {
		DEBUG_LOG("CloseHandle(%p)\n", hObject);
		auto data = handles::dataFromHandle(hObject, true);
		if (data.type == handles::TYPE_FILE) {
			FILE *fp = (FILE *) data.ptr;
			if (!(fp == stdin || fp == stdout || fp == stderr)) {
				fclose(fp);
			}
	} else if (data.type == handles::TYPE_MAPPED) {
		auto *mapping = reinterpret_cast<MappingObject *>(data.ptr);
		if (mapping) {
			mapping->closed = true;
			tryReleaseMapping(mapping);
		}
	} else if (data.type == handles::TYPE_PROCESS) {
			delete (processes::Process*) data.ptr;
		} else if (data.type == handles::TYPE_TOKEN) {
			advapi32::releaseToken(data.ptr);
		} else if (data.type == handles::TYPE_MUTEX) {
			releaseMutexObject(reinterpret_cast<MutexObject *>(data.ptr));
		}
		return TRUE;
	}

	DWORD WIN_FUNC GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart) {
		DEBUG_LOG("GetFullPathNameA(%s) ", lpFileName);
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpFileName));
		std::string absStr = files::pathToWindows(absPath);
		DEBUG_LOG("-> %s\n", absStr.c_str());

		// Enough space?
		if ((absStr.size() + 1) <= nBufferLength) {
			strcpy(lpBuffer, absStr.c_str());

			// Do we need to fill in FilePart?
			if (lpFilePart) {
				*lpFilePart = 0;
				if (!std::filesystem::is_directory(absPath)) {
					*lpFilePart = strrchr(lpBuffer, '\\');
					if (*lpFilePart)
						*lpFilePart += 1;
				}
			}

			return absStr.size();
		} else {
			return absStr.size() + 1;
		}
	}

	DWORD WIN_FUNC GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart) {
		std::string narrowName = wideStringToString(lpFileName);
		DEBUG_LOG("GetFullPathNameW(%s) ", narrowName.c_str());

		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(narrowName.c_str()));
		std::string absStr = files::pathToWindows(absPath);
		auto absStrW = stringToWideString(absStr.c_str());
		DEBUG_LOG("-> %s\n", absStr.c_str());

		size_t len = wstrlen(absStrW.data());
		if (nBufferLength == 0 || nBufferLength <= len) {
			if (lpFilePart) {
				*lpFilePart = nullptr;
			}
			return len + 1;
		}

		wstrncpy(lpBuffer, absStrW.data(), len + 1);
		if (lpFilePart) {
			*lpFilePart = nullptr;
			std::error_code ec;
			bool pathIsDir = std::filesystem::is_directory(absPath, ec) && !ec;
			if (!pathIsDir) {
				uint16_t *lastSlash = wstrrchr(lpBuffer, '\\');
				if (lastSlash && *(lastSlash + 1) != 0) {
					*lpFilePart = lastSlash + 1;
				} else if (!lastSlash && len > 0) {
					*lpFilePart = lpBuffer;
				}
			}
		}
		wibo::lastError = ERROR_SUCCESS;
		return len;
	}

	/**
	 * @brief GetShortPathNameA: Retrieves the short path form of the specified path
	 *
	 * @param[in] lpszLongPath The path string
	 * @param[out] lpszShortPath A pointer to a buffer to receive
	 * @param[in] cchBuffer The size of the buffer that lpszShortPath points to
	 * @return unsigned int
	 */
	unsigned int WIN_FUNC GetShortPathNameA(const char* lpszLongPath, char* lpszShortPath, unsigned int cchBuffer) {
		DEBUG_LOG("GetShortPathNameA(%s)...\n",lpszShortPath);
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpszLongPath));
		std::string absStr = files::pathToWindows(absPath);

		if (absStr.length() + 1 > cchBuffer)
		{
			return absStr.length()+1;
		}
		else
		{
			strcpy(lpszShortPath, absStr.c_str());
			return absStr.length();
		}
	}

	DWORD WIN_FUNC GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer) {
		std::string longPath = wideStringToString(lpszLongPath);
		DEBUG_LOG("GetShortPathNameW(%s)\n", longPath.c_str());
		std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(longPath.c_str()));
		std::string absStr = files::pathToWindows(absPath);
		auto absStrW = stringToWideString(absStr.c_str());
		size_t len = wstrlen(absStrW.data());
		if (cchBuffer == 0 || cchBuffer <= len) {
			return len + 1;
		}
		wstrncpy(lpszShortPath, absStrW.data(), len + 1);
		wibo::lastError = ERROR_SUCCESS;
		return len;
	}

	using random_shorts_engine = std::independent_bits_engine<std::default_random_engine, sizeof(unsigned short) * 8, unsigned short>;

	unsigned int WIN_FUNC GetTempFileNameA(LPSTR lpPathName, LPSTR lpPrefixString, unsigned int uUnique, LPSTR lpTempFileName) {
		DEBUG_LOG("GetTempFileNameA\n");
		if (lpPathName == 0) {
			return 0;
		}
		if (strlen(lpPathName) > MAX_PATH - 14) {
			wibo::lastError = ERROR_BUFFER_OVERFLOW;
			return 0;
		}
		char uniqueStr[20];
		std::filesystem::path path;

		if (uUnique == 0) {
			std::random_device rd;
			random_shorts_engine rse(rd());
			while(true) {
				uUnique = rse();
				if (uUnique == 0) {
					continue;
				}
				snprintf(uniqueStr, sizeof(uniqueStr), "%.3s%X.TMP", lpPrefixString, uUnique);
				path = files::pathFromWindows(lpPathName) / uniqueStr;
				// Atomically create it if it doesn't exist
				int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
				if (fd >= 0) {
					close(fd);
					break;
				}
			}
		}
		else {
			snprintf(uniqueStr, sizeof(uniqueStr), "%.3s%X.TMP", lpPrefixString, uUnique & 0xFFFF);
			path = files::pathFromWindows(lpPathName) / uniqueStr;
		}
		strncpy(lpTempFileName, files::pathToWindows(path).c_str(), MAX_PATH);
		return uUnique;
	}

	DWORD WIN_FUNC GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
		DEBUG_LOG("GetTempPathA\n");

		if ((nBufferLength == 0) || (lpBuffer == 0)) {
			return 0;
		}

		const char* tmp_dir;
		if (!(tmp_dir = getenv("WIBO_TMP_DIR"))) {
			tmp_dir = "Z:\\tmp\\";
		}

		strcpy(lpBuffer, tmp_dir);
		return strlen(tmp_dir);
	}

	struct FILETIME {
		unsigned int dwLowDateTime;
		unsigned int dwHighDateTime;
	};

	static const uint64_t UNIX_TIME_ZERO = 11644473600LL * 10000000;
	static const FILETIME defaultFiletime = {
		(unsigned int)UNIX_TIME_ZERO,
		(unsigned int)(UNIX_TIME_ZERO >> 32)
	};

	static FILETIME fileTimeFromDuration(uint64_t ticks100ns) {
		FILETIME result;
		result.dwLowDateTime = (unsigned int)(ticks100ns & 0xFFFFFFFF);
		result.dwHighDateTime = (unsigned int)(ticks100ns >> 32);
		return result;
	}

	static FILETIME fileTimeFromTimeval(const struct timeval &value) {
		uint64_t total = 0;
		if (value.tv_sec > 0 || value.tv_usec > 0) {
			total = (uint64_t)value.tv_sec * 10000000ULL + (uint64_t)value.tv_usec * 10ULL;
		}
		return fileTimeFromDuration(total);
	}

	static FILETIME fileTimeFromTimespec(const struct timespec &value) {
		uint64_t total = 0;
		if (value.tv_sec > 0 || value.tv_nsec > 0) {
			total = (uint64_t)value.tv_sec * 10000000ULL + (uint64_t)value.tv_nsec / 100ULL;
		}
		return fileTimeFromDuration(total);
	}

	template<typename CharType>
	struct WIN32_FIND_DATA {
		uint32_t dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		uint32_t nFileSizeHigh;
		uint32_t nFileSizeLow;
		uint32_t dwReserved0;
		uint32_t dwReserved1;
		CharType cFileName[260];
		CharType cAlternateFileName[14];
	};

	struct FindFirstFileHandle {
		std::filesystem::directory_iterator it;
		std::string pattern;
	};

	bool findNextFile(FindFirstFileHandle* handle) {
		// Check if iterator is valid before using it
		if (!handle || handle->it == std::filesystem::directory_iterator()) {
			return false;
		}

		// Early return if pattern is empty
		if (handle->pattern.empty()) {
			return false;
		}

		// Look for a matching file with the pattern
		while (handle->it != std::filesystem::directory_iterator()) {
			std::filesystem::path path = *handle->it;
			if (fnmatch(handle->pattern.c_str(), path.filename().c_str(), 0) == 0) {
				return true;
			}
			handle->it++;
		}

		return false;
	}

	void setFindFileDataFromPath(WIN32_FIND_DATA<char>* data, const std::filesystem::path &path) {
		auto status = std::filesystem::status(path);
		uint64_t fileSize = 0;
		data->dwFileAttributes = 0;
		if (std::filesystem::is_directory(status)) {
			data->dwFileAttributes |= 0x10;
		}
		if (std::filesystem::is_regular_file(status)) {
			data->dwFileAttributes |= 0x80;
			fileSize = std::filesystem::file_size(path);
		}
		data->nFileSizeHigh = (uint32_t)(fileSize >> 32);
		data->nFileSizeLow = (uint32_t)fileSize;
		auto fileName = path.filename().string();
		assert(fileName.size() < 260);
		strcpy(data->cFileName, fileName.c_str());
		strcpy(data->cAlternateFileName, "8P3FMTFN.BAD");
	}

	void setFindFileDataFromPathW(WIN32_FIND_DATA<uint16_t>* data, const std::filesystem::path &path){
		auto status = std::filesystem::status(path);
		uint64_t fileSize = 0;
		data->dwFileAttributes = 0;
		if (std::filesystem::is_directory(status)) {
			data->dwFileAttributes |= 0x10;
		}
		if (std::filesystem::is_regular_file(status)) {
			data->dwFileAttributes |= 0x80;
			fileSize = std::filesystem::file_size(path);
		}
		data->nFileSizeHigh = (uint32_t)(fileSize >> 32);
		data->nFileSizeLow = (uint32_t)fileSize;
		auto fileName = path.filename().string();
		assert(fileName.size() < 260);
		auto wideFileName = stringToWideString(fileName.c_str());
		wstrcpy(data->cFileName, wideFileName.data());
		auto wideBad = stringToWideString("8P3FMTFN.BAD");
		wstrcpy(data->cAlternateFileName, wideBad.data());
	}

	void *WIN_FUNC FindFirstFileA(const char *lpFileName, WIN32_FIND_DATA<char> *lpFindFileData) {
		// This should handle wildcards too, but whatever.
		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("FindFirstFileA %s (%s)\n", lpFileName, path.c_str());

		lpFindFileData->ftCreationTime = defaultFiletime;
		lpFindFileData->ftLastAccessTime = defaultFiletime;
		lpFindFileData->ftLastWriteTime = defaultFiletime;

		auto status = std::filesystem::status(path);
		if (status.type() == std::filesystem::file_type::regular) {
			setFindFileDataFromPath(lpFindFileData, path);
			return (void *) 1;
		}

		// If the parent path is empty then we assume the parent path is the current directory.
		auto parent_path = path.parent_path();
		if (parent_path == "") {
			parent_path = ".";
		}

		if (!std::filesystem::exists(parent_path)) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}

		auto *handle = new FindFirstFileHandle();

		std::filesystem::directory_iterator it(parent_path);
		handle->it = it;
		handle->pattern = path.filename().string();

		if (!findNextFile(handle)) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			delete handle;
			return INVALID_HANDLE_VALUE;
		}

		setFindFileDataFromPath(lpFindFileData, *handle->it++);
		return handle;
	}

	void *WIN_FUNC FindFirstFileW(const uint16_t *lpFileName, WIN32_FIND_DATA<uint16_t> *lpFindFileData) {
		std::string filename = wideStringToString(lpFileName);
		// This should handle wildcards too, but whatever.
		auto path = files::pathFromWindows(filename.c_str());
		DEBUG_LOG("FindFirstFileW %s (%s)\n", filename.c_str(), path.c_str());

		lpFindFileData->ftCreationTime = defaultFiletime;
		lpFindFileData->ftLastAccessTime = defaultFiletime;
		lpFindFileData->ftLastWriteTime = defaultFiletime;

		auto status = std::filesystem::status(path);
		if (status.type() == std::filesystem::file_type::regular) {
			setFindFileDataFromPathW(lpFindFileData, path);
			return (void *) 1;
		}

		// If the parent path is empty then we assume the parent path is the current directory.
		auto parent_path = path.parent_path();
		if (parent_path == "") {
			parent_path = ".";
		}

		if (!std::filesystem::exists(parent_path)) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}

		auto *handle = new FindFirstFileHandle();

		std::filesystem::directory_iterator it(parent_path);
		handle->it = it;
		handle->pattern = path.filename().string();

		if (!findNextFile(handle)) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			delete handle;
			return INVALID_HANDLE_VALUE;
		}

		setFindFileDataFromPathW(lpFindFileData, *handle->it++);
		return handle;
	}

	typedef enum _FINDEX_INFO_LEVELS {
		FindExInfoStandard,
		FindExInfoBasic,
		FindExInfoMaxInfoLevel
	} FINDEX_INFO_LEVELS;

	typedef enum _FINDEX_SEARCH_OPS {
		FindExSearchNameMatch,
		FindExSearchLimitToDirectories,
		FindExSearchLimitToDevices,
		FindExSearchMaxSearchOp
	} FINDEX_SEARCH_OPS;

	void *WIN_FUNC FindFirstFileExA(const char *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, void *lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, void *lpSearchFilter, unsigned int dwAdditionalFlags) {
		assert(fInfoLevelId == FindExInfoStandard);

		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("FindFirstFileExA %s (%s)\n", lpFileName, path.c_str());

		return FindFirstFileA(lpFileName, (WIN32_FIND_DATA<char> *) lpFindFileData);
	}

	int WIN_FUNC FindNextFileA(void *hFindFile, WIN32_FIND_DATA<char> *lpFindFileData) {
		DEBUG_LOG("FindNextFileA(%p, %p)\n", hFindFile, lpFindFileData);
		// Special value from FindFirstFileA
		if (hFindFile == (void *) 1) {
			wibo::lastError = ERROR_NO_MORE_FILES;
			return 0;
		}

		auto *handle = (FindFirstFileHandle *) hFindFile;
		if (!findNextFile(handle)) {
			wibo::lastError = ERROR_NO_MORE_FILES;
			return 0;
		}

		setFindFileDataFromPath(lpFindFileData, *handle->it++);
		return 1;
	}

	int WIN_FUNC FindClose(void *hFindFile) {
		DEBUG_LOG("FindClose\n");
		if (hFindFile != (void *) 1) {
			delete (FindFirstFileHandle *)hFindFile;
		}
		return 1;
	}

	unsigned int WIN_FUNC GetFileAttributesA(const char *lpFileName) {
		auto path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("GetFileAttributesA(%s)... (%s)\n", lpFileName, path.c_str());

		// See ole32::CoCreateInstance
		if (endsWith(path, "/license.dat")) {
			DEBUG_LOG("MWCC license override\n");
			return 0x80; // FILE_ATTRIBUTE_NORMAL
		}

		auto status = std::filesystem::status(path);

		wibo::lastError = 0;

		switch (status.type()) {
			case std::filesystem::file_type::regular:
				DEBUG_LOG("File exists\n");
				return 0x80; // FILE_ATTRIBUTE_NORMAL
			case std::filesystem::file_type::directory:
				return 0x10; // FILE_ATTRIBUTE_DIRECTORY
			case std::filesystem::file_type::not_found:
			default:
				DEBUG_LOG("File does not exist\n");
				wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
				return 0xFFFFFFFF; // INVALID_FILE_ATTRIBUTES
		}
	}

	unsigned int WIN_FUNC GetFileAttributesW(const uint16_t* lpFileName) {
		DEBUG_LOG("GetFileAttributesW(");
		std::string str = wideStringToString(lpFileName);
		DEBUG_LOG("%s)\n", str.c_str());
		return GetFileAttributesA(str.c_str());
	}

	unsigned short WIN_FUNC GetUserDefaultUILanguage(){
		DEBUG_LOG("STUB GetUserDefaultUILanguage\n");
		return 0;
	}

	unsigned int WIN_FUNC WriteFile(void *hFile, const void *lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int *lpNumberOfBytesWritten, void *lpOverlapped) {
		DEBUG_LOG("WriteFile(%p, %d)\n", hFile, nNumberOfBytesToWrite);
		assert(!lpOverlapped);
		wibo::lastError = 0;

		FILE *fp = files::fpFromHandle(hFile);
		size_t written = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, fp);
		if (lpNumberOfBytesWritten)
			*lpNumberOfBytesWritten = written;

#if 0
		printf("writing:\n");
		for (unsigned int i = 0; i < nNumberOfBytesToWrite; i++) {
			printf("%c", ((const char*)lpBuffer)[i]);
		}
		printf("\n");
#endif

		if (written == 0)
			wibo::lastError = 29; // ERROR_WRITE_FAULT

		return (written == nNumberOfBytesToWrite);
	}

	unsigned int WIN_FUNC ReadFile(void *hFile, void *lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int *lpNumberOfBytesRead, void *lpOverlapped) {
		DEBUG_LOG("ReadFile %p %d\n", hFile, nNumberOfBytesToRead);
		assert(!lpOverlapped);
		wibo::lastError = 0;

		FILE *fp = files::fpFromHandle(hFile);
		size_t read = fread(lpBuffer, 1, nNumberOfBytesToRead, fp);
		*lpNumberOfBytesRead = read;
		return 1;
	}

	enum {
		CREATE_NEW = 1,
		CREATE_ALWAYS = 2,
		OPEN_EXISTING = 3,
		OPEN_ALWAYS = 4,
		TRUNCATE_EXISTING = 5,
	};
	void *WIN_FUNC CreateFileA(
			const char* lpFileName,
			unsigned int dwDesiredAccess,
			unsigned int dwShareMode,
			void *lpSecurityAttributes,
			unsigned int dwCreationDisposition,
			unsigned int dwFlagsAndAttributes,
			void *hTemplateFile) {
		std::string path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, creationDisposition=%u, flagsAndAttributes=%u)\n",
				lpFileName, path.c_str(),
				dwDesiredAccess, dwShareMode, lpSecurityAttributes,
				dwCreationDisposition, dwFlagsAndAttributes);

		wibo::lastError = 0; // possibly overwritten later in this function

		// Based on https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#parameters
		// and this table: https://stackoverflow.com/a/14469641
		bool fileExists = (access(path.c_str(), F_OK) == 0);
		bool shouldTruncate = false;
		switch (dwCreationDisposition) {
			case CREATE_ALWAYS:
				if (fileExists) {
					wibo::lastError = 183; // ERROR_ALREADY_EXISTS
					shouldTruncate = true; // "The function overwrites the file"
					// Function succeeds
				}
				break;
			case CREATE_NEW:
				if (fileExists) {
					wibo::lastError = 80; // ERROR_FILE_EXISTS
					return INVALID_HANDLE_VALUE;
				}
				break;
			case OPEN_ALWAYS:
				if (fileExists) {
					wibo::lastError = 183; // ERROR_ALREADY_EXISTS
					// Function succeeds
				}
				break;
			case OPEN_EXISTING:
				if (!fileExists) {
					wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
					return INVALID_HANDLE_VALUE;
				}
				break;
			case TRUNCATE_EXISTING:
				shouldTruncate = true;
				if (!fileExists) {
					wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
					return INVALID_HANDLE_VALUE;
				}
				break;
			default:
				assert(0);
		}

		FILE *fp;
		if (dwDesiredAccess == 0x80000000) { // read
			fp = fopen(path.c_str(), "rb");
		} else if (dwDesiredAccess == 0x40000000) { // write
			if (shouldTruncate || !fileExists) {
				fp = fopen(path.c_str(), "wb");
			} else {
				// There is no way to fopen with only write permissions
				// and without truncating the file...
				fp = fopen(path.c_str(), "rb+");
			}
		} else if (dwDesiredAccess == 0xc0000000) { // read/write
			if (shouldTruncate || !fileExists) {
				fp = fopen(path.c_str(), "wb+");
			} else {
				fp = fopen(path.c_str(), "rb+");
			}
		} else {
			assert(0);
		}

		if (fp) {
			void *handle = files::allocFpHandle(fp);
			DEBUG_LOG("-> %p\n", handle);
			return handle;
		} else {
			setLastErrorFromErrno();
			return INVALID_HANDLE_VALUE;
		}
	}

	void *WIN_FUNC CreateFileW(const uint16_t *lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode,
				   void *lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes,
				   void *hTemplateFile) {
		DEBUG_LOG("CreateFileW -> ");
		const auto lpFileNameA = wideStringToString(lpFileName);
		return CreateFileA(lpFileNameA.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
				   dwFlagsAndAttributes, hTemplateFile);
	}

	void *WIN_FUNC CreateFileMappingA(
			void *hFile,
			void *lpFileMappingAttributes,
			unsigned int flProtect,
			unsigned int dwMaximumSizeHigh,
			unsigned int dwMaximumSizeLow,
			const char *lpName) {
		DEBUG_LOG("CreateFileMappingA(%p, %p, %u, %u, %u, %s)\n", hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName ? lpName : "(null)");
		(void) lpFileMappingAttributes;
		(void) lpName;

		auto mapping = new MappingObject();
		mapping->protect = flProtect;

		uint64_t size = ((uint64_t) dwMaximumSizeHigh << 32) | dwMaximumSizeLow;
		if (flProtect != 0x02 /* PAGE_READONLY */ && flProtect != 0x04 /* PAGE_READWRITE */ && flProtect != 0x08 /* PAGE_WRITECOPY */) {
			DEBUG_LOG("CreateFileMappingA: unsupported protection 0x%x\n", flProtect);
			wibo::lastError = ERROR_INVALID_PARAMETER;
			closeMappingIfPossible(mapping);
			return nullptr;
		}

		if (hFile == (void *) -1) {
			mapping->anonymous = true;
			mapping->fd = -1;
			if (size == 0) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				closeMappingIfPossible(mapping);
				return nullptr;
			}
			mapping->maxSize = size;
		} else {
			FILE *fp = files::fpFromHandle(hFile);
			if (!fp) {
				wibo::lastError = ERROR_INVALID_HANDLE;
				closeMappingIfPossible(mapping);
				return nullptr;
			}
			int originalFd = fileno(fp);
			if (originalFd == -1) {
				setLastErrorFromErrno();
				closeMappingIfPossible(mapping);
				return nullptr;
			}
			int dupFd = fcntl(originalFd, F_DUPFD_CLOEXEC, 0);
			if (dupFd == -1) {
				setLastErrorFromErrno();
				closeMappingIfPossible(mapping);
				return nullptr;
			}
			mapping->fd = dupFd;
			if (size == 0) {
				int64_t fileSize = getFileSize(hFile);
				if (fileSize < 0) {
					closeMappingIfPossible(mapping);
					return nullptr;
				}
				size = static_cast<uint64_t>(fileSize);
			}
			mapping->maxSize = size;
		}

		wibo::lastError = ERROR_SUCCESS;
		return handles::allocDataHandle({handles::TYPE_MAPPED, mapping, static_cast<size_t>(mapping->maxSize)});
	}

	void *WIN_FUNC CreateFileMappingW(
			void *hFile,
			void *lpFileMappingAttributes,
			unsigned int flProtect,
			unsigned int dwMaximumSizeHigh,
			unsigned int dwMaximumSizeLow,
			const uint16_t *lpName) {
		std::string name = wideStringToString(lpName);
		return CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName ? name.c_str() : nullptr);
	}

	constexpr unsigned int FILE_MAP_COPY = 0x00000001;
	constexpr unsigned int FILE_MAP_WRITE = 0x00000002;
	constexpr unsigned int FILE_MAP_READ = 0x00000004;
	constexpr unsigned int FILE_MAP_EXECUTE = 0x00000020;

	void *WIN_FUNC MapViewOfFile(
			void *hFileMappingObject,
			unsigned int dwDesiredAccess,
			unsigned int dwFileOffsetHigh,
			unsigned int dwFileOffsetLow,
			unsigned int dwNumberOfBytesToMap) {
		DEBUG_LOG("MapViewOfFile(%p, 0x%x, %u, %u, %u)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

		handles::Data data = handles::dataFromHandle(hFileMappingObject, false);
		if (data.type != handles::TYPE_MAPPED) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return nullptr;
		}
		auto *mapping = reinterpret_cast<MappingObject *>(data.ptr);
		if (!mapping) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return nullptr;
		}
		if (mapping->closed) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return nullptr;
		}

		uint64_t offset = ((uint64_t) dwFileOffsetHigh << 32) | dwFileOffsetLow;
		if (mapping->anonymous && offset != 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		size_t maxSize = mapping->maxSize;
		uint64_t length = dwNumberOfBytesToMap;
		if (length == 0) {
			if (maxSize == 0) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			if (offset > maxSize) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			length = maxSize - offset;
		}
		if (length == 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		if (maxSize && offset + length > maxSize) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}

		int prot = PROT_READ;
		bool wantWrite = (dwDesiredAccess & FILE_MAP_WRITE) != 0;
		bool wantExecute = (dwDesiredAccess & FILE_MAP_EXECUTE) != 0;

		if (mapping->protect == 0x04 /* PAGE_READWRITE */) {
			if (wantWrite) {
				prot |= PROT_WRITE;
			}
		} else { // read-only or write copy
			if (wantWrite && !(dwDesiredAccess & FILE_MAP_COPY)) {
				wibo::lastError = ERROR_ACCESS_DENIED;
				return nullptr;
			}
		}
		if (wantExecute) {
			prot |= PROT_EXEC;
		}

		int flags = 0;
		if (mapping->anonymous) {
			flags |= MAP_ANONYMOUS;
		}
		flags |= (dwDesiredAccess & FILE_MAP_COPY) ? MAP_PRIVATE : MAP_SHARED;

		size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
		off_t alignedOffset = mapping->anonymous ? 0 : static_cast<off_t>(offset & ~static_cast<uint64_t>(pageSize - 1));
		size_t offsetDelta = static_cast<size_t>(offset - alignedOffset);
		size_t mapLength = static_cast<size_t>(length + offsetDelta);
		if (mapLength < length) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}

		int mmapFd = mapping->anonymous ? -1 : mapping->fd;
		void *mapBase = mmap(nullptr, mapLength, prot, flags, mmapFd, alignedOffset);
		if (mapBase == MAP_FAILED) {
			setLastErrorFromErrno();
			return nullptr;
		}
		void *viewPtr = static_cast<uint8_t *>(mapBase) + offsetDelta;
		g_viewInfo[viewPtr] = ViewInfo{mapBase, mapLength, mapping};
		mapping->refCount++;
		wibo::lastError = ERROR_SUCCESS;
		return viewPtr;
	}

	int WIN_FUNC UnmapViewOfFile(void *lpBaseAddress) {
		DEBUG_LOG("UnmapViewOfFile(%p)\n", lpBaseAddress);
		auto it = g_viewInfo.find(lpBaseAddress);
		if (it == g_viewInfo.end()) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}
		ViewInfo info = it->second;
		g_viewInfo.erase(it);
		if (info.mapBase && info.mapLength) {
			munmap(info.mapBase, info.mapLength);
		}
		if (info.owner && info.owner->refCount > 0) {
			info.owner->refCount--;
			tryReleaseMapping(info.owner);
		}
		wibo::lastError = ERROR_SUCCESS;
		return 1;
	}

	BOOL WIN_FUNC DeleteFileA(const char* lpFileName) {
		if (!lpFileName) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		std::string path = files::pathFromWindows(lpFileName);
		DEBUG_LOG("DeleteFileA %s (%s)\n", lpFileName, path.c_str());
		if (unlink(path.c_str()) == 0) {
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		setLastErrorFromErrno();
		return FALSE;
	}

	BOOL WIN_FUNC DeleteFileW(const uint16_t *lpFileName) {
		if (!lpFileName) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		std::string name = wideStringToString(lpFileName);
		return DeleteFileA(name.c_str());
	}

	DWORD WIN_FUNC SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
		DEBUG_LOG("SetFilePointer(%p, %d, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
		assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
		FILE *fp = files::fpFromHandle(hFile);
		wibo::lastError = ERROR_SUCCESS;
		int r = fseek(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

		if (r < 0) {
			if (errno == EINVAL)
				wibo::lastError = ERROR_NEGATIVE_SEEK;
			else
				wibo::lastError = ERROR_INVALID_PARAMETER;
			return INVALID_SET_FILE_POINTER;
		}

		r = ftell(fp);
		assert(r >= 0);
		return r;
	}

	BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER lDistanceToMove, PLARGE_INTEGER lpDistanceToMoveHigh,
								   DWORD dwMoveMethod) {
		assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
		DEBUG_LOG("SetFilePointerEx(%p, %ld, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
		FILE *fp = files::fpFromHandle(hFile);
		wibo::lastError = ERROR_SUCCESS;
		int r = fseeko64(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

		if (r < 0) {
			if (errno == EINVAL)
				wibo::lastError = ERROR_NEGATIVE_SEEK;
			else
				wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}

		r = ftell(fp);
		assert(r >= 0);
		return TRUE;
	}

	int WIN_FUNC SetEndOfFile(void *hFile) {
		DEBUG_LOG("SetEndOfFile\n");
		FILE *fp = files::fpFromHandle(hFile);
		fflush(fp);
		return ftruncate(fileno(fp), ftell(fp)) == 0;
	}

	int WIN_FUNC CreateDirectoryA(const char *lpPathName, void *lpSecurityAttributes) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("CreateDirectoryA(%s, %p)\n", path.c_str(), lpSecurityAttributes);
		return mkdir(path.c_str(), 0755) == 0;
	}

	int WIN_FUNC RemoveDirectoryA(const char *lpPathName) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("RemoveDirectoryA(%s)\n", path.c_str());
		return rmdir(path.c_str()) == 0;
	}

	int WIN_FUNC SetFileAttributesA(const char *lpPathName, unsigned int dwFileAttributes) {
		std::string path = files::pathFromWindows(lpPathName);
		DEBUG_LOG("SetFileAttributesA(%s, %u)\n", path.c_str(), dwFileAttributes);
		return 1;
	}

	unsigned int WIN_FUNC GetFileSize(void *hFile, unsigned int *lpFileSizeHigh) {
		DEBUG_LOG("GetFileSize\n");
		int64_t size = getFileSize(hFile);
		if (size == -1) {
			return 0xFFFFFFFF; // INVALID_FILE_SIZE
		}
		DEBUG_LOG("-> %ld\n", size);
		if (lpFileSizeHigh != nullptr) {
			*lpFileSizeHigh = size >> 32;
		}
		return size;
	}

	/*
	 * Time
	 */
	int WIN_FUNC GetFileTime(void *hFile, FILETIME *lpCreationTime, FILETIME *lpLastAccessTime, FILETIME *lpLastWriteTime) {
		DEBUG_LOG("GetFileTime %p %p %p\n", lpCreationTime, lpLastAccessTime, lpLastWriteTime);
		if (lpCreationTime) *lpCreationTime = defaultFiletime;
		if (lpLastAccessTime) *lpLastAccessTime = defaultFiletime;
		if (lpLastWriteTime) *lpLastWriteTime = defaultFiletime;
		return 1;
	}

	struct SYSTEMTIME {
		short wYear;
		short wMonth;
		short wDayOfWeek;
		short wDay;
		short wHour;
		short wMinute;
		short wSecond;
		short wMilliseconds;
	};

	void WIN_FUNC GetSystemTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetSystemTime\n");

		time_t t = time(NULL);
		struct tm *tm = gmtime(&t);
		assert(tm != NULL);

		lpSystemTime->wYear = tm->tm_year + 1900;
		lpSystemTime->wMonth = tm->tm_mon + 1;
		lpSystemTime->wDayOfWeek = tm->tm_wday;
		lpSystemTime->wDay = tm->tm_mday;
		lpSystemTime->wHour = tm->tm_hour;
		lpSystemTime->wMinute = tm->tm_min;
		lpSystemTime->wSecond = tm->tm_sec;
		lpSystemTime->wMilliseconds = 0;
	}

	void WIN_FUNC GetLocalTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetLocalTime\n");

		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		assert(tm != NULL);

		lpSystemTime->wYear = tm->tm_year + 1900;
		lpSystemTime->wMonth = tm->tm_mon + 1;
		lpSystemTime->wDayOfWeek = tm->tm_wday;
		lpSystemTime->wDay = tm->tm_mday;
		lpSystemTime->wHour = tm->tm_hour;
		lpSystemTime->wMinute = tm->tm_min;
		lpSystemTime->wSecond = tm->tm_sec;
		lpSystemTime->wMilliseconds = 0;
	}

	int WIN_FUNC SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, FILETIME *lpFileTime) {
		DEBUG_LOG("SystemTimeToFileTime\n");
		*lpFileTime = defaultFiletime;
		return 1;
	}

	void WIN_FUNC GetSystemTimeAsFileTime(FILETIME *lpSystemTimeAsFileTime) {
		DEBUG_LOG("GetSystemTimeAsFileTime\n");
		*lpSystemTimeAsFileTime = defaultFiletime;
	}

	int WIN_FUNC GetTickCount() {
		DEBUG_LOG("GetTickCount\n");
		return 0;
	}

	int WIN_FUNC FileTimeToSystemTime(const FILETIME *lpFileTime, SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("FileTimeToSystemTime\n");
		lpSystemTime->wYear = 0;
		lpSystemTime->wMonth = 0;
		lpSystemTime->wDayOfWeek = 0;
		lpSystemTime->wDay = 0;
		lpSystemTime->wHour = 0;
		lpSystemTime->wMinute = 0;
		lpSystemTime->wSecond = 0;
		lpSystemTime->wMilliseconds = 0;
		return 1;
	}

	int WIN_FUNC SetFileTime(void *hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime, const FILETIME *lpLastWriteTime) {
		DEBUG_LOG("SetFileTime\n");
		return 1;
	}

	int WIN_FUNC FileTimeToLocalFileTime(const FILETIME *lpFileTime, FILETIME *lpLocalFileTime) {
		DEBUG_LOG("FileTimeToLocalFileTime\n");
		// we live on Iceland
		*lpLocalFileTime = *lpFileTime;
		return 1;
	}

	struct BY_HANDLE_FILE_INFORMATION {
		unsigned long dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		unsigned long dwVolumeSerialNumber;
		unsigned long nFileSizeHigh;
		unsigned long nFileSizeLow;
		unsigned long nNumberOfLinks;
		unsigned long nFileIndexHigh;
		unsigned long nFileIndexLow;
	};

	int WIN_FUNC GetFileInformationByHandle(void *hFile, BY_HANDLE_FILE_INFORMATION *lpFileInformation) {
		DEBUG_LOG("GetFileInformationByHandle(%p, %p)\n", hFile, lpFileInformation);
		FILE* fp = files::fpFromHandle(hFile);
		if (fp == nullptr) {
			wibo::lastError = 6; // ERROR_INVALID_HANDLE
			return 0;
		}
		struct stat64 st{};
		if (fstat64(fileno(fp), &st)) {
			setLastErrorFromErrno();
			return 0;
		}

		if (lpFileInformation != nullptr) {
			lpFileInformation->dwFileAttributes = 0;
			if (S_ISDIR(st.st_mode)) {
				lpFileInformation->dwFileAttributes |= 0x10;
			}
			if (S_ISREG(st.st_mode)) {
				lpFileInformation->dwFileAttributes |= 0x80;
			}
			lpFileInformation->ftCreationTime = defaultFiletime;
			lpFileInformation->ftLastAccessTime = defaultFiletime;
			lpFileInformation->ftLastWriteTime = defaultFiletime;
			lpFileInformation->dwVolumeSerialNumber = 0;
			lpFileInformation->nFileSizeHigh = (unsigned long) (st.st_size >> 32);
			lpFileInformation->nFileSizeLow = (unsigned long) st.st_size;
			lpFileInformation->nNumberOfLinks = 0;
			lpFileInformation->nFileIndexHigh = 0;
			lpFileInformation->nFileIndexLow = 0;
		}
		return 1;
	}

	struct TIME_ZONE_INFORMATION {
		int Bias;
		short StandardName[32];
		SYSTEMTIME StandardDate;
		int StandardBias;
		short DaylightName[32];
		SYSTEMTIME DaylightDate;
		int DaylightBias;
	};

	int WIN_FUNC GetTimeZoneInformation(TIME_ZONE_INFORMATION *lpTimeZoneInformation) {
		DEBUG_LOG("GetTimeZoneInformation\n");
		memset(lpTimeZoneInformation, 0, sizeof(*lpTimeZoneInformation));
		return 0;
	}

	/*
	 * Console Nonsense
	 */
	int WIN_FUNC GetConsoleMode(void *hConsoleHandle, unsigned int *lpMode) {
		DEBUG_LOG("GetConsoleMode(%p)\n", hConsoleHandle);
		*lpMode = 0;
		return 1;
	}

	unsigned int WIN_FUNC GetConsoleOutputCP(){
		DEBUG_LOG("GetConsoleOutputCP\n");
		return 65001; // UTF-8
	}

	unsigned int WIN_FUNC SetConsoleCtrlHandler(void *HandlerRoutine, unsigned int Add) {
		DEBUG_LOG("STUB SetConsoleCtrlHandler\n");
		// This is a function that gets called when doing ^C
		// We might want to call this later (being mindful that it'll be stdcall I think)

		// For now, just pretend we did the thing
		return 1;
	}

	struct CONSOLE_SCREEN_BUFFER_INFO {
		int16_t dwSize_x;
		int16_t dwSize_y;
		int16_t dwCursorPosition_x;
		int16_t dwCursorPosition_y;
		uint16_t wAttributes;
		int16_t srWindow_left;
		int16_t srWindow_top;
		int16_t srWindow_right;
		int16_t srWindow_bottom;
		int16_t dwMaximumWindowSize_x;
		int16_t dwMaximumWindowSize_y;
	};

	unsigned int WIN_FUNC GetConsoleScreenBufferInfo(void *hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo) {
		DEBUG_LOG("GetConsoleScreenBufferInfo(%p, %p)\n", hConsoleOutput, lpConsoleScreenBufferInfo);
		// Tell a lie
		// mwcc doesn't care about anything else
		lpConsoleScreenBufferInfo->dwSize_x = 80;
		lpConsoleScreenBufferInfo->dwSize_y = 25;

		return 1;
	}

	BOOL WIN_FUNC WriteConsoleW(HANDLE hConsoleOutput, LPCWSTR lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten,
								LPVOID lpReserved) {
		DEBUG_LOG("WriteConsoleW(%p, %p, %u, %p, %p)\n", hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten,
				  lpReserved);
		const auto str = wideStringToString(lpBuffer, nNumberOfCharsToWrite);
		FILE *fp = files::fpFromHandle(hConsoleOutput);
		if (fp == stdout || fp == stderr) {
			fprintf(fp, "%s", str.c_str());
			if (lpNumberOfCharsWritten) {
				*lpNumberOfCharsWritten = nNumberOfCharsToWrite;
			}
			return TRUE;
		}
		if (lpNumberOfCharsWritten) {
			*lpNumberOfCharsWritten = 0;
		}
		return FALSE;
	}

	unsigned int WIN_FUNC GetSystemDirectoryA(char *lpBuffer, unsigned int uSize) {
		DEBUG_LOG("GetSystemDirectoryA(%p, %u)\n", lpBuffer, uSize);
		if (lpBuffer == nullptr) {
			return 0;
		}

		const char* systemDir = "C:\\Windows\\System32";
		const auto len = strlen(systemDir);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (uSize < len + 1) {
			return len + 1;
		}

		strcpy(lpBuffer, systemDir);
		return len;
	}

	unsigned int WIN_FUNC GetWindowsDirectoryA(char *lpBuffer, unsigned int uSize) {
		DEBUG_LOG("GetWindowsDirectoryA(%p, %u)\n", lpBuffer, uSize);
		if (lpBuffer == nullptr) {
			return 0;
		}

		const char* systemDir = "C:\\Windows";
		const auto len = strlen(systemDir);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (uSize < len + 1) {
			return len + 1;
		}

		strcpy(lpBuffer, systemDir);
		return len;
	}

	unsigned int WIN_FUNC GetCurrentDirectoryA(unsigned int uSize, char *lpBuffer) {
		DEBUG_LOG("GetCurrentDirectoryA(%u, %p)", uSize, lpBuffer);

		std::filesystem::path cwd = std::filesystem::current_path();
		std::string path = files::pathToWindows(cwd);

		// If the buffer is too small, return the required buffer size.
		// (Add 1 to include the NUL terminator)
		if (path.size() + 1 > uSize) {
			DEBUG_LOG(" !! Buffer too small: %i, %i\n", path.size() + 1, uSize);
			return path.size() + 1;
		}

		DEBUG_LOG(" -> %s\n", path.c_str());
		strcpy(lpBuffer, path.c_str());
		return path.size();
	}

	unsigned int WIN_FUNC GetCurrentDirectoryW(unsigned int uSize, uint16_t *lpBuffer) {
		DEBUG_LOG("GetCurrentDirectoryW\n");

		std::filesystem::path cwd = std::filesystem::current_path();
		std::string path = files::pathToWindows(cwd);

		assert(path.size() < uSize);
		const char *pathCstr = path.c_str();
		for (size_t i = 0; i < path.size() + 1; i++) {
			lpBuffer[i] = pathCstr[i] & 0xFF;
		}
		return path.size();
	}

	HMODULE WIN_FUNC GetModuleHandleA(LPCSTR lpModuleName) {
		DEBUG_LOG("GetModuleHandleA(%s)\n", lpModuleName);

		if (!lpModuleName) {
			// If lpModuleName is NULL, GetModuleHandle returns a handle to the file
			// used to create the calling process (.exe file).
			// This handle needs to equal the actual image buffer, from which data can be read.
			return wibo::mainModule->imageBuffer;
		}

		HMODULE module = wibo::findLoadedModule(lpModuleName);
		wibo::lastError = module ? ERROR_SUCCESS : ERROR_MOD_NOT_FOUND;
		return module;
	}

	HMODULE WIN_FUNC GetModuleHandleW(LPCWSTR lpModuleName) {
		DEBUG_LOG("GetModuleHandleW -> ");
		if (lpModuleName) {
			const auto lpModuleNameA = wideStringToString(lpModuleName);
			return GetModuleHandleA(lpModuleNameA.c_str());
		} else {
			return GetModuleHandleA(nullptr);
		}
	}

	DWORD WIN_FUNC GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
		DEBUG_LOG("GetModuleFileNameA (hModule=%p, nSize=%i)\n", hModule, nSize);
		if (lpFilename == nullptr) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		std::string path;
		if (wibo::isMainModule(hModule)) {
			const auto exePath = files::pathFromWindows(wibo::argv[0]);
			const auto absPath = std::filesystem::absolute(exePath);
			path = files::pathToWindows(absPath);
		} else {
			auto *info = wibo::moduleInfoFromHandle(hModule);
			if (!info) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return 0;
			}
			if (!info->resolvedPath.empty()) {
				path = files::pathToWindows(info->resolvedPath);
			} else {
				path = info->originalName;
			}
		}
		const size_t len = path.size();
		if (nSize == 0) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}

		const size_t copyLen = std::min(len, nSize - 1);
		memcpy(lpFilename, path.c_str(), copyLen);
		if (copyLen < nSize) {
			lpFilename[copyLen] = 0;
		}
		if (copyLen < len) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return nSize;
		}

		wibo::lastError = ERROR_SUCCESS;
		return copyLen;
	}

	DWORD WIN_FUNC GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
		DEBUG_LOG("GetModuleFileNameW (hModule=%p, nSize=%i)\n", hModule, nSize);
		if (lpFilename == nullptr) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		std::string path;
		if (wibo::isMainModule(hModule)) {
			const auto exePath = files::pathFromWindows(wibo::argv[0]);
			const auto absPath = std::filesystem::absolute(exePath);
			path = files::pathToWindows(absPath);
		} else {
			auto *info = wibo::moduleInfoFromHandle(hModule);
			if (!info) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return 0;
			}
			if (!info->resolvedPath.empty()) {
				path = files::pathToWindows(info->resolvedPath);
			} else {
				path = info->originalName;
			}
		}
		if (nSize == 0) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}

		auto wide = stringToWideString(path.c_str());
		if (wide.empty()) {
			wide.push_back(0);
		}
		const size_t len = wide.size() - 1;
		const size_t copyLen = std::min(len, static_cast<size_t>(nSize - 1));
		for (size_t i = 0; i < copyLen; i++) {
			lpFilename[i] = wide[i];
		}
		if (copyLen < static_cast<size_t>(nSize)) {
			lpFilename[copyLen] = 0;
		}
		if (copyLen < len) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return nSize;
		}

		wibo::lastError = ERROR_SUCCESS;
		return copyLen;
	}

	static wibo::Executable *module_executable_for_resource(void *hModule) {
		if (!hModule) {
			hModule = GetModuleHandleA(nullptr);
		}
		return wibo::executableFromModule((HMODULE) hModule);
    }

	static void *find_resource_internal(void *hModule,
										 const wibo::ResourceIdentifier &type,
										 const wibo::ResourceIdentifier &name,
										 std::optional<uint16_t> language) {
		auto *exe = module_executable_for_resource(hModule);
		if (!exe) {
			wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
			return nullptr;
		}
		wibo::ResourceLocation loc;
		if (!exe->findResource(type, name, language, loc)) {
			return nullptr;
		}
		return const_cast<void *>(loc.dataEntry);
	}

	void *WIN_FUNC FindResourceA(void *hModule, const char *lpName, const char *lpType) {
		DEBUG_LOG("FindResourceA %p %p %p\n", hModule, lpName, lpType);
		auto type = wibo::resourceIdentifierFromAnsi(lpType);
		auto name = wibo::resourceIdentifierFromAnsi(lpName);
		return find_resource_internal(hModule, type, name, std::nullopt);
	}

	void *WIN_FUNC FindResourceExA(void *hModule, const char *lpType, const char *lpName, uint16_t wLanguage) {
		DEBUG_LOG("FindResourceExA %p %p %p %u\n", hModule, lpName, lpType, wLanguage);
		auto type = wibo::resourceIdentifierFromAnsi(lpType);
		auto name = wibo::resourceIdentifierFromAnsi(lpName);
		return find_resource_internal(hModule, type, name, wLanguage);
	}

	void *WIN_FUNC FindResourceW(void *hModule, const uint16_t *lpName, const uint16_t *lpType) {
		DEBUG_LOG("FindResourceW %p\n", hModule);
		auto type = wibo::resourceIdentifierFromWide(lpType);
		auto name = wibo::resourceIdentifierFromWide(lpName);
		return find_resource_internal(hModule, type, name, std::nullopt);
	}

	void *WIN_FUNC FindResourceExW(void *hModule, const uint16_t *lpType, const uint16_t *lpName, uint16_t wLanguage) {
		DEBUG_LOG("FindResourceExW %p %u\n", hModule, wLanguage);
		auto type = wibo::resourceIdentifierFromWide(lpType);
		auto name = wibo::resourceIdentifierFromWide(lpName);
		return find_resource_internal(hModule, type, name, wLanguage);
	}

	void* WIN_FUNC LoadResource(void* hModule, void* res) {
		DEBUG_LOG("LoadResource %p %p\n", hModule, res);
		if (!res) {
			wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
			return nullptr;
		}
		auto *exe = module_executable_for_resource(hModule);
		if (!exe || !exe->rsrcBase) {
			wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
			return nullptr;
		}
		const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(res);
		if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		return const_cast<void *>(exe->fromRVA<const void>(entry->offsetToData));
	}

	BOOL WIN_FUNC GetDiskFreeSpaceExW(const uint16_t* lpDirectoryName,
		uint64_t* lpFreeBytesAvailableToCaller, uint64_t* lpTotalNumberOfBytes, uint64_t* lpTotalNumberOfFreeBytes){
		if(!lpDirectoryName) return false;

		std::string directoryName = wideStringToString(lpDirectoryName);
		DEBUG_LOG("GetDiskFreeSpaceExW %s\n", directoryName.c_str());

		struct statvfs buf;
		if(statvfs(directoryName.c_str(), &buf) != 0){
			return false;
		}

		if (lpFreeBytesAvailableToCaller)
		    *lpFreeBytesAvailableToCaller = (uint64_t)buf.f_bavail * buf.f_bsize;
		if (lpTotalNumberOfBytes)
		    *lpTotalNumberOfBytes = (uint64_t)buf.f_blocks * buf.f_bsize;
		if (lpTotalNumberOfFreeBytes)
		    *lpTotalNumberOfFreeBytes = (uint64_t)buf.f_bfree * buf.f_bsize;

		DEBUG_LOG("\t-> available bytes %llu, total bytes %llu, total free bytes %llu\n",
			*lpFreeBytesAvailableToCaller, *lpTotalNumberOfBytes, *lpTotalNumberOfFreeBytes);
		return true;
	}

	void* WIN_FUNC LockResource(void* res) {
		DEBUG_LOG("LockResource %p\n", res);
		return res;
	}

	unsigned int WIN_FUNC SizeofResource(void* hModule, void* res) {
		DEBUG_LOG("SizeofResource %p %p\n", hModule, res);
		if (!res) {
			wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
			return 0;
		}
		auto *exe = module_executable_for_resource(hModule);
		if (!exe || !exe->rsrcBase) {
			wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
			return 0;
		}
		const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(res);
		if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}
		return entry->size;
	}

	HMODULE WIN_FUNC LoadLibraryA(LPCSTR lpLibFileName) {
		DEBUG_LOG("LoadLibraryA(%s)\n", lpLibFileName);
		return wibo::loadModule(lpLibFileName);
	}

	HMODULE WIN_FUNC LoadLibraryW(LPCWSTR lpLibFileName) {
		DEBUG_LOG("LoadLibraryW\n");
		if (!lpLibFileName) {
			return nullptr;
		}
		auto filename = wideStringToString(lpLibFileName);
		return LoadLibraryA(filename.c_str());
	}

	HMODULE WIN_FUNC LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
		assert(!hFile);
		DEBUG_LOG("LoadLibraryExW(%x) -> ", dwFlags);
		const auto filename = wideStringToString(lpLibFileName);
		return LoadLibraryA(filename.c_str());
	}

	BOOL WIN_FUNC FreeLibrary(HMODULE hLibModule) {
		DEBUG_LOG("FreeLibrary(%p)\n", hLibModule);
		wibo::freeModule(hLibModule);
		return TRUE;
	}

	const unsigned int MAJOR_VER = 6, MINOR_VER = 2, BUILD_NUMBER = 0; // Windows 8

	unsigned int WIN_FUNC GetVersion() {
		DEBUG_LOG("GetVersion\n");
		return MAJOR_VER | MINOR_VER << 8 | 5 << 16 | BUILD_NUMBER << 24;
	}

	typedef struct {
		uint32_t dwOSVersionInfoSize;
		uint32_t dwMajorVersion;
		uint32_t dwMinorVersion;
		uint32_t dwBuildNumber;
		uint32_t dwPlatformId;
		char szCSDVersion[128];
		/**
		 * If dwOSVersionInfoSize indicates more members (i.e. we have an OSVERSIONINFOEXA):
		 * uint16_t wServicePackMajor;
		 * uint16_t wServicePackMinor;
		 * uint16_t wSuiteMask;
		 * uint8_t wProductType;
		 * uint8_t wReserved;
		 */
	} OSVERSIONINFOA;

	int WIN_FUNC GetVersionExA(OSVERSIONINFOA* lpVersionInformation) {
		DEBUG_LOG("GetVersionExA\n");
		memset(lpVersionInformation, 0, lpVersionInformation->dwOSVersionInfoSize);
		lpVersionInformation->dwMajorVersion = MAJOR_VER;
		lpVersionInformation->dwMinorVersion = MINOR_VER;
		lpVersionInformation->dwBuildNumber = BUILD_NUMBER;
		lpVersionInformation->dwPlatformId = 2;
		return 1;
	}

	void *WIN_FUNC HeapCreate(unsigned int flOptions, unsigned int dwInitialSize, unsigned int dwMaximumSize) {
		DEBUG_LOG("HeapCreate %u %u %u\n", flOptions, dwInitialSize, dwMaximumSize);
		if (flOptions & 0x00000001) {
			// HEAP_NO_SERIALIZE
		}
		if (flOptions & 0x00040000) {
			// HEAP_CREATE_ENABLE_EXECUTE
		}
		if (flOptions & 0x00000004) {
			// HEAP_GENERATE_EXCEPTIONS
		}

		// return a dummy value
		wibo::lastError = 0;
		return (void *) 0x100006;
	}

	static int translateProtect(DWORD flProtect) {
		switch (flProtect) {
		case 0x01: /* PAGE_NOACCESS */
			return PROT_NONE;
		case 0x02: /* PAGE_READONLY */
			return PROT_READ;
		case 0x04: /* PAGE_READWRITE */
			return PROT_READ | PROT_WRITE;
		case 0x08: /* PAGE_WRITECOPY */
			return PROT_READ | PROT_WRITE;
		case 0x10: /* PAGE_EXECUTE */
			return PROT_EXEC;
		case 0x20: /* PAGE_EXECUTE_READ */
			return PROT_READ | PROT_EXEC;
		case 0x40: /* PAGE_EXECUTE_READWRITE */
			return PROT_READ | PROT_WRITE | PROT_EXEC;
		case 0x80: /* PAGE_EXECUTE_WRITECOPY */
			return PROT_READ | PROT_WRITE | PROT_EXEC;
		default:
			DEBUG_LOG("Unhandled flProtect: %u, defaulting to RW\n", flProtect);
			return PROT_READ | PROT_WRITE;
		}
	}

	void *WIN_FUNC VirtualAlloc(void *lpAddress, unsigned int dwSize, unsigned int flAllocationType, unsigned int flProtect) {
		DEBUG_LOG("VirtualAlloc %p %u %u %u\n", lpAddress, dwSize, flAllocationType, flProtect);

		int prot = translateProtect(flProtect);

		int flags = MAP_PRIVATE | MAP_ANONYMOUS; // MAP_ANONYMOUS ensures the memory is zeroed out
		if (lpAddress != NULL) {
			flags |= MAP_FIXED;
		}

		void* result = mmap(lpAddress, dwSize, prot, flags, -1, 0);
		// Windows only fences off the lower 2GB of the 32-bit address space for the private use of processes.
		assert(result < (void*)0x80000000);
		if (result == MAP_FAILED) {
			DEBUG_LOG("mmap failed\n");
			return NULL;
		}
		else {
			DEBUG_LOG("-> %p\n", result);
			return result;
		}
	}

	unsigned int WIN_FUNC VirtualFree(void *lpAddress, unsigned int dwSize, int dwFreeType) {
		DEBUG_LOG("VirtualFree %p %u %i\n", lpAddress, dwSize, dwFreeType);
		return 1;
	}

	BOOL WIN_FUNC VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
		DEBUG_LOG("VirtualProtect %p %zu %u\n", lpAddress, dwSize, flNewProtect);
		if (!lpAddress || dwSize == 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		if (lpflOldProtect)
			*lpflOldProtect = flNewProtect;
		size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
		uintptr_t base = reinterpret_cast<uintptr_t>(lpAddress) & ~(pageSize - 1);
		size_t length = ((reinterpret_cast<uintptr_t>(lpAddress) + dwSize) - base + pageSize - 1) & ~(pageSize - 1);
		int prot = translateProtect(flNewProtect);
		if (mprotect(reinterpret_cast<void *>(base), length, prot) != 0) {
			perror("VirtualProtect/mprotect");
			return FALSE;
		}
		return TRUE;
	}

	typedef struct _MEMORY_BASIC_INFORMATION {
		void *BaseAddress;
		void *AllocationBase;
		DWORD AllocationProtect;
		size_t RegionSize;
		DWORD State;
		DWORD Protect;
		DWORD Type;
	} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

	SIZE_T WIN_FUNC VirtualQuery(const void *lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
		DEBUG_LOG("VirtualQuery %p %zu\n", lpAddress, dwLength);
		if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) {
			return 0;
		}
		memset(lpBuffer, 0, sizeof(MEMORY_BASIC_INFORMATION));
		lpBuffer->BaseAddress = const_cast<LPVOID>(lpAddress);
		lpBuffer->AllocationBase = lpBuffer->BaseAddress;
		lpBuffer->AllocationProtect = 0x04; // PAGE_READWRITE
		lpBuffer->RegionSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
		lpBuffer->State = 0x1000; // MEM_COMMIT
		lpBuffer->Protect = 0x04; // PAGE_READWRITE
		lpBuffer->Type = 0x20000; // MEM_PRIVATE
		return sizeof(MEMORY_BASIC_INFORMATION);
	}

	unsigned int WIN_FUNC GetProcessWorkingSetSize(void *hProcess, unsigned int *lpMinimumWorkingSetSize, unsigned int *lpMaximumWorkingSetSize) {
		DEBUG_LOG("GetProcessWorkingSetSize\n");
		// A pointer to a variable that receives the minimum working set size of the specified process, in bytes.
		// The virtual memory manager attempts to keep at least this much memory resident in the process whenever the process is active.
		*lpMinimumWorkingSetSize = 32*1024*1024; // 32MB

		// A pointer to a variable that receives the maximum working set size of the specified process, in bytes.
		// The virtual memory manager attempts to keep no more than this much memory resident in the process whenever
		// the process is active when memory is in short supply.
		*lpMaximumWorkingSetSize = 128*1024*1024; // 128MB

		// If the function succeeds, the return value is nonzero.
		return 1;
	}

	unsigned int WIN_FUNC SetProcessWorkingSetSize(void *hProcess, unsigned int dwMinimumWorkingSetSize, unsigned int dwMaximumWorkingSetSize) {
		DEBUG_LOG("SetProcessWorkingSetSize: min %u, max: %u\n", dwMinimumWorkingSetSize, dwMaximumWorkingSetSize);
		return 1;
	}

	typedef struct _STARTUPINFOA {
		unsigned int   cb;
		char		  *lpReserved;
		char		  *lpDesktop;
		char		  *lpTitle;
		unsigned int   dwX;
		unsigned int   dwY;
		unsigned int   dwXSize;
		unsigned int   dwYSize;
		unsigned int   dwXCountChars;
		unsigned int   dwYCountChars;
		unsigned int   dwFillAttribute;
		unsigned int   dwFlags;
		unsigned short wShowWindow;
		unsigned short cbReserved2;
		unsigned char  lpReserved2;
		void		  *hStdInput;
		void		  *hStdOutput;
		void		  *hStdError;
	} STARTUPINFOA, *LPSTARTUPINFOA;

	void WIN_FUNC GetStartupInfoA(STARTUPINFOA *lpStartupInfo) {
		DEBUG_LOG("GetStartupInfoA\n");
		memset(lpStartupInfo, 0, sizeof(STARTUPINFOA));
	}

	typedef struct _STARTUPINFOW {
		unsigned int  cb;
		unsigned short *lpReserved;
		unsigned short *lpDesktop;
		unsigned short *lpTitle;
		unsigned int  dwX;
		unsigned int  dwY;
		unsigned int  dwXSize;
		unsigned int  dwYSize;
		unsigned int  dwXCountChars;
		unsigned int  dwYCountChars;
		unsigned int  dwFillAttribute;
		unsigned int  dwFlags;
		unsigned short wShowWindow;
		unsigned short cbReserved2;
		unsigned char lpReserved2;
		void *hStdInput;
		void *hStdOutput;
		void *hStdError;
	} STARTUPINFOW, *LPSTARTUPINFOW;

	void WIN_FUNC GetStartupInfoW(_STARTUPINFOW *lpStartupInfo) {
		DEBUG_LOG("GetStartupInfoW\n");
		memset(lpStartupInfo, 0, sizeof(_STARTUPINFOW));
	}

	BOOL WIN_FUNC SetThreadStackGuarantee(PULONG StackSizeInBytes) {
		DEBUG_LOG("STUB: SetThreadStackGuarantee(%p)\n", StackSizeInBytes);
		return TRUE;
	}

	HANDLE WIN_FUNC GetCurrentThread() {
		DEBUG_LOG("STUB: GetCurrentThread\n");
		return (HANDLE)0x100007;
	}

	HRESULT WIN_FUNC SetThreadDescription(HANDLE hThread, const void * /* PCWSTR */ lpThreadDescription) {
		DEBUG_LOG("STUB: SetThreadDescription(%p, %p)\n", hThread, lpThreadDescription);
		return S_OK;
	}

	HANDLE WIN_FUNC CreateMutexW(void *lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
		std::string nameLog;
		if (lpName) {
			nameLog = wideStringToString(reinterpret_cast<const uint16_t *>(lpName));
		} else {
			nameLog = "<unnamed>";
		}
		DEBUG_LOG("CreateMutexW(name=%s, initialOwner=%d)\n", nameLog.c_str(), bInitialOwner);
		(void)lpMutexAttributes;

		std::u16string name = makeMutexName(lpName);
		MutexObject *obj = nullptr;
		bool alreadyExists = false;
		{
			std::lock_guard<std::mutex> lock(mutexRegistryLock);
			if (!name.empty()) {
				auto it = namedMutexes.find(name);
				if (it != namedMutexes.end()) {
					obj = it->second;
					obj->refCount++;
					alreadyExists = true;
				}
			}
			if (!obj) {
				obj = new MutexObject();
				pthread_mutexattr_t attr;
				pthread_mutexattr_init(&attr);
				pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
				pthread_mutex_init(&obj->mutex, &attr);
				pthread_mutexattr_destroy(&attr);
				obj->ownerValid = false;
				obj->recursionCount = 0;
				obj->name = name;
				obj->refCount = 1;
				if (!name.empty()) {
					namedMutexes[name] = obj;
				}
			}
		}

		if (!alreadyExists && bInitialOwner) {
			pthread_mutex_lock(&obj->mutex);
			obj->owner = pthread_self();
			obj->ownerValid = true;
			obj->recursionCount = 1;
		}

		HANDLE handle = handles::allocDataHandle({handles::TYPE_MUTEX, obj, 0});
		wibo::lastError = alreadyExists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
		return handle;
	}

	BOOL WIN_FUNC ReleaseMutex(HANDLE hMutex) {
		DEBUG_LOG("ReleaseMutex(%p)\n", hMutex);
		auto data = handles::dataFromHandle(hMutex, false);
		if (data.type != handles::TYPE_MUTEX) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		auto *obj = reinterpret_cast<MutexObject *>(data.ptr);
		pthread_t self = pthread_self();
		if (!obj->ownerValid || !pthread_equal(obj->owner, self)) {
			wibo::lastError = ERROR_NOT_OWNER;
			return FALSE;
		}
		if (obj->recursionCount > 0) {
			obj->recursionCount--;
		}
		if (obj->recursionCount == 0) {
			obj->ownerValid = false;
		}
		pthread_mutex_unlock(&obj->mutex);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	BOOL WIN_FUNC GetThreadTimes(HANDLE hThread,
				     FILETIME *lpCreationTime,
				     FILETIME *lpExitTime,
				     FILETIME *lpKernelTime,
				     FILETIME *lpUserTime) {
		DEBUG_LOG("GetThreadTimes(%p, %p, %p, %p, %p)\n",
			hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

		if (!lpKernelTime || !lpUserTime) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}

		bool isPseudoCurrentThread = hThread == (HANDLE)0x100007 || hThread == (HANDLE)0xFFFFFFFE || hThread == (HANDLE)0 || hThread == (HANDLE)0xFFFFFFFF;
		if (!isPseudoCurrentThread) {
			DEBUG_LOG("GetThreadTimes: unsupported handle %p\n", hThread);
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}

		if (lpCreationTime) {
			*lpCreationTime = defaultFiletime;
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

	unsigned short WIN_FUNC GetFileType(void *hFile) {
		DEBUG_LOG("GetFileType %p\n", hFile);
		return 1; // FILE_TYPE_DISK
	}

	unsigned int WIN_FUNC SetHandleCount(unsigned int uNumber) {
		DEBUG_LOG("SetHandleCount %p\n", uNumber);
		return uNumber + 10;
	}

	void WIN_FUNC Sleep(DWORD dwMilliseconds) {
		DEBUG_LOG("Sleep(%u)\n", dwMilliseconds);
		usleep(static_cast<useconds_t>(dwMilliseconds) * 1000);
	}

	unsigned int WIN_FUNC GetACP() {
		DEBUG_LOG("GetACP\n");
		// return 65001;    // UTF-8
		// return 1200;     // Unicode (BMP of ISO 10646)
		return 28591;       // Latin1 (ISO/IEC 8859-1)
	}

	typedef struct _cpinfo {
		unsigned int  MaxCharSize;
		unsigned char DefaultChar[2];
		unsigned char LeadByte[12];
	} CPINFO, *LPCPINFO;

	unsigned int WIN_FUNC GetCPInfo(unsigned int codePage, CPINFO* lpCPInfo) {
		DEBUG_LOG("GetCPInfo: %u\n", codePage);
		lpCPInfo->MaxCharSize = 1;
		lpCPInfo->DefaultChar[0] = 0;
		return 1; // success
	}

	unsigned int WIN_FUNC WideCharToMultiByte(unsigned int codePage, unsigned int dwFlags, uint16_t *lpWideCharStr, int cchWideChar, char *lpMultiByteStr, int cbMultiByte, char *lpDefaultChar, unsigned int *lpUsedDefaultChar) {
		DEBUG_LOG("WideCharToMultiByte(codePage=%u, flags=%x, wcs=%p, wideChar=%d, mbs=%p, multiByte=%d, defaultChar=%p, usedDefaultChar=%p)\n", codePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

		if (cchWideChar == -1) {
			cchWideChar = wstrlen(lpWideCharStr) + 1;
		}

		if (cbMultiByte == 0) {
			return cchWideChar;
		}
		for (int i = 0; i < cchWideChar; i++) {
			lpMultiByteStr[i] = lpWideCharStr[i] & 0xFF;
		}

		if (wibo::debugEnabled) {
			std::string s(lpMultiByteStr, lpMultiByteStr + cchWideChar);
			DEBUG_LOG("Converted string: [%s] (len %d)\n", s.c_str(), cchWideChar);
		}

		return cchWideChar;
	}

	unsigned int WIN_FUNC MultiByteToWideChar(unsigned int codePage, unsigned int dwFlags, const char *lpMultiByteStr, int cbMultiByte, uint16_t *lpWideCharStr, int cchWideChar) {
		DEBUG_LOG("MultiByteToWideChar(codePage=%u, dwFlags=%u, multiByte=%d, wideChar=%d)\n", codePage, dwFlags, cbMultiByte, cchWideChar);

		if (cbMultiByte == -1) {
			cbMultiByte = strlen(lpMultiByteStr) + 1;
		}

		// assert (dwFlags == 1); // MB_PRECOMPOSED
		if (cchWideChar == 0) {
			return cbMultiByte;
		}

		if (wibo::debugEnabled) {
			std::string s(lpMultiByteStr, lpMultiByteStr + cbMultiByte);
			DEBUG_LOG("Converting string: [%s] (len %d)\n", s.c_str(), cbMultiByte);
		}

		assert(cbMultiByte <= cchWideChar);
		for (int i = 0; i < cbMultiByte; i++) {
			lpWideCharStr[i] = lpMultiByteStr[i] & 0xFF;
		}
		return cbMultiByte;
	}

	unsigned int WIN_FUNC GetStringTypeW(unsigned int dwInfoType, const uint16_t *lpSrcStr, int cchSrc, uint16_t *lpCharType) {
		DEBUG_LOG("GetStringTypeW (dwInfoType=%u, lpSrcStr=%p, cchSrc=%i, lpCharType=%p)\n", dwInfoType, lpSrcStr, cchSrc, lpCharType);

		assert(dwInfoType == 1); // CT_CTYPE1

		if (cchSrc < 0)
			cchSrc = wstrlen(lpSrcStr);

		for (int i = 0; i < cchSrc; i++) {
			uint16_t c = lpSrcStr[i];
			assert(c < 256);

			bool upper = ('A' <= c && c <= 'Z');
			bool lower = ('a' <= c && c <= 'z');
			bool alpha = (lower || upper);
			bool digit = ('0' <= c && c <= '9');
			bool space = (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f' || c == '\v');
			bool blank = (c == ' ' || c == '\t');
			bool hex = (digit || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f'));
			bool cntrl = (c < 0x20 || c == 127);
			bool punct = (!cntrl && !digit && !alpha);
			lpCharType[i] = (upper ? 1 : 0) | (lower ? 2 : 0) | (digit ? 4 : 0) | (space ? 8 : 0) | (punct ? 0x10 : 0) | (cntrl ? 0x20 : 0) | (blank ? 0x40 : 0) | (hex ? 0x80 : 0) | (alpha ? 0x100 : 0);
		}

		return 1;
	}

	unsigned int WIN_FUNC FreeEnvironmentStringsW(void *penv) {
		DEBUG_LOG("FreeEnvironmentStringsW: %p\n", penv);
		free(penv);
		return 1;
	}

	unsigned int WIN_FUNC IsProcessorFeaturePresent(unsigned int processorFeature) {
		DEBUG_LOG("IsProcessorFeaturePresent: %u\n", processorFeature);

		if (processorFeature == 0) // PF_FLOATING_POINT_PRECISION_ERRATA
			return 1;
		if (processorFeature == 10) // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
			return 1;
		if (processorFeature == 23) // PF_FASTFAIL_AVAILABLE (__fastfail() supported)
			return 1;

		// sure.. we have that feature...
		DEBUG_LOG("  IsProcessorFeaturePresent: we don't know about feature %u, lying...\n", processorFeature);
		return 1;
	}

	FARPROC WIN_FUNC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
		FARPROC result;
		const auto proc = reinterpret_cast<uintptr_t>(lpProcName);
		if (proc & ~0xFFFF) {
			DEBUG_LOG("GetProcAddress(%p, %s) ", hModule, lpProcName);
			result = wibo::resolveFuncByName(hModule, lpProcName);
		} else {
			DEBUG_LOG("GetProcAddress(%p, %u) ", hModule, proc);
			result = wibo::resolveFuncByOrdinal(hModule, static_cast<uint16_t>(proc));
		}
		DEBUG_LOG("-> %p\n", result);
		return result;
	}

	void *WIN_FUNC HeapAlloc(void *hHeap, unsigned int dwFlags, size_t dwBytes) {
		DEBUG_LOG("HeapAlloc(heap=%p, flags=%x, bytes=%u) ", hHeap, dwFlags, dwBytes);

		void *mem = doAlloc(dwBytes, dwFlags & 8);
		DEBUG_LOG("-> %p\n", mem);
		return mem;
	}

	void *WIN_FUNC HeapReAlloc(void *hHeap, unsigned int dwFlags, void *lpMem, size_t dwBytes) {
		DEBUG_LOG("HeapReAlloc(heap=%p, flags=%x, mem=%p, bytes=%u) ", hHeap, dwFlags, lpMem, dwBytes);
		void *ret = doRealloc(lpMem, dwBytes, dwFlags & 8);
		DEBUG_LOG("-> %p\n", ret);
		return ret;
	}

	unsigned int WIN_FUNC HeapSize(void *hHeap, unsigned int dwFlags, void *lpMem) {
		DEBUG_LOG("HeapSize(heap=%p, flags=%x, mem=%p)\n", hHeap, dwFlags, lpMem);
		return mi_usable_size(lpMem);
	}

	void *WIN_FUNC GetProcessHeap() {
		DEBUG_LOG("GetProcessHeap\n");
		return (void *) 0x100006;
	}

	int WIN_FUNC HeapSetInformation(void *HeapHandle, int HeapInformationClass, void *HeapInformation, size_t HeapInformationLength) {
		DEBUG_LOG("HeapSetInformation %p %d\n", HeapHandle, HeapInformationClass);
		return 1;
	}

	unsigned int WIN_FUNC HeapFree(void *hHeap, unsigned int dwFlags, void *lpMem) {
		DEBUG_LOG("HeapFree(heap=%p, flags=%x, mem=%p)\n", hHeap, dwFlags, lpMem);
		free(lpMem);
		return 1;
	}

	unsigned int WIN_FUNC FormatMessageA(unsigned int dwFlags, void *lpSource, unsigned int dwMessageId,
										 unsigned int dwLanguageId, char *lpBuffer, unsigned int nSize, va_list *argument) {

		DEBUG_LOG("FormatMessageA: flags: %u, message id: %u\n", dwFlags, dwMessageId);

		if (dwFlags & 0x00000100) {
			// FORMAT_MESSAGE_ALLOCATE_BUFFER
		} else if (dwFlags & 0x00002000) {
			// FORMAT_MESSAGE_ARGUMENT_ARRAY
		} else if (dwFlags & 0x00000800) {
			// FORMAT_MESSAGE_FROM_HMODULE
		} else if (dwFlags & 0x00000400) {
			// FORMAT_MESSAGE_FROM_STRING
		} else if (dwFlags & 0x00001000) {
			// FORMAT_MESSAGE_FROM_SYSTEM
			std::string message = std::system_category().message(dwMessageId);
			size_t length = message.length();
			strcpy(lpBuffer, message.c_str());
			return length;
		} else if (dwFlags & 0x00000200) {
			// FORMAT_MESSAGE_IGNORE_INSERTS
		} else {
			// unhandled?
		}

		*lpBuffer = '\0';
		return 0;
	}

	int WIN_FUNC GetComputerNameA(char *lpBuffer, unsigned int *nSize) {
		DEBUG_LOG("GetComputerNameA\n");
		if (!nSize || !lpBuffer) {
			if (nSize) {
				*nSize = 0;
			}
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}
		constexpr unsigned int required = 9; // "COMPNAME" + null terminator
		if (*nSize < required) {
			*nSize = required;
			wibo::lastError = ERROR_BUFFER_OVERFLOW;
			return 0;
		}
		strcpy(lpBuffer, "COMPNAME");
		*nSize = required - 1;
		wibo::lastError = ERROR_SUCCESS;
		return 1;
	}

	int WIN_FUNC GetComputerNameW(uint16_t *lpBuffer, unsigned int *nSize) {
		DEBUG_LOG("GetComputerNameW\n");
		if (!nSize || !lpBuffer) {
			if (nSize) {
				*nSize = 0;
			}
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}
		constexpr uint16_t computerName[] = {'C', 'O', 'M', 'P', 'N', 'A', 'M', 'E', 0};
		constexpr unsigned int nameLength = 8;
		constexpr unsigned int required = nameLength + 1;
		if (*nSize < required) {
			*nSize = required;
			wibo::lastError = ERROR_BUFFER_OVERFLOW;
			return 0;
		}
		wstrncpy(lpBuffer, computerName, required);
		*nSize = nameLength;
		wibo::lastError = ERROR_SUCCESS;
		return 1;
	}

	void *WIN_FUNC EncodePointer(void *Ptr) {
		return Ptr;
	}

	void *WIN_FUNC DecodePointer(void *Ptr) {
		return Ptr;
	}

	BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName) {
		DEBUG_LOG("SetDllDirectoryA(%s)\n", lpPathName);
		if (!lpPathName || lpPathName[0] == '\0') {
			wibo::clearDllDirectoryOverride();
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}

		auto hostPath = files::pathFromWindows(lpPathName);
		if (hostPath.empty() || !std::filesystem::exists(hostPath)) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return FALSE;
		}

		wibo::setDllDirectoryOverride(std::filesystem::absolute(hostPath));
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	int WIN_FUNC CompareStringA(int Locale, unsigned int dwCmpFlags, const char *lpString1, int cchCount1, const char *lpString2, int cchCount2) {
		if (cchCount1 < 0)
			cchCount1 = strlen(lpString1);
		if (cchCount2 < 0)
			cchCount2 = strlen(lpString2);
		std::string str1(lpString1, lpString1 + cchCount1);
		std::string str2(lpString2, lpString2 + cchCount2);

		DEBUG_LOG("CompareStringA: '%s' vs '%s' (%u)\n", str1.c_str(), str2.c_str(), dwCmpFlags);
		return doCompareString(str1, str2, dwCmpFlags);
	}

	int WIN_FUNC CompareStringW(int Locale, unsigned int dwCmpFlags, const uint16_t *lpString1, int cchCount1, const uint16_t *lpString2, int cchCount2) {
		std::string str1 = wideStringToString(lpString1, cchCount1);
		std::string str2 = wideStringToString(lpString2, cchCount2);

		DEBUG_LOG("CompareStringW: '%s' vs '%s' (%u)\n", str1.c_str(), str2.c_str(), dwCmpFlags);
		return doCompareString(str1, str2, dwCmpFlags);
	}

	int WIN_FUNC IsValidCodePage(unsigned int CodePage) {
		DEBUG_LOG("IsValidCodePage: %u\n", CodePage);
		// Returns a nonzero value if the code page is valid, or 0 if the code page is invalid.
		return 1;
	}

	int WIN_FUNC IsValidLocale(unsigned int Locale, unsigned int dwFlags) {
		DEBUG_LOG("IsValidLocale: %u %u\n", Locale, dwFlags);
		// Yep, this locale is both supported (dwFlags=1) and installed (dwFlags=2)
		return 1;
	}

	std::string str_for_LCType(int LCType) {
		// https://www.pinvoke.net/default.aspx/Enums/LCType.html
		if (LCType == 4100) { // LOCALE_IDEFAULTANSICODEPAGE
			// Latin1; ref GetACP
			return "28591";
		}
		if (LCType == 4097) { // LOCALE_SENGLANGUAGE
			return "Lang";
		}
		if (LCType == 4098) { // LOCALE_SENGCOUNTRY
			return "Country";
		}
		if (LCType == 0x1) { // LOCALE_ILANGUAGE
			return "0001";
		}
		if (LCType == 0x15) { // LOCALE_SINTLSYMBOL
			return "Currency";
		}
		if (LCType == 0x14) { // LOCALE_SCURRENCY
			return "sCurrency";
		}
		if (LCType == 0x16) { // LOCALE_SMONDECIMALSEP
			return ".";
		}
		if (LCType == 0x17) { // LOCALE_SMONTHOUSANDSEP
			return ",";
		}
		if (LCType == 0x18) { // LOCALE_SMONGROUPING
			return ";";
		}
		if (LCType == 0x50) { // LOCALE_SPOSITIVESIGN
			return "";
		}
		if (LCType == 0x51) { // LOCALE_SNEGATIVESIGN
			return "-";
		}
		if (LCType == 0x1A) { // LOCALE_IINTLCURRDIGITS
			return "2";
		}
		if (LCType == 0x19) { // LOCALE_ICURRDIGITS
			return "2";
		}

		DEBUG_LOG("STUB: LCType 0x%X not implemented\n", LCType);
		return "";
	}

	int WIN_FUNC GetLocaleInfoA(unsigned int Locale, int LCType, LPSTR lpLCData, int cchData) {
		DEBUG_LOG("GetLocaleInfoA %d %d\n", Locale, LCType);
		std::string ret = str_for_LCType(LCType);
		size_t len = ret.size() + 1;

		if (!cchData) {
			return len;
		} else {
			assert(len <= (size_t) cchData);
			memcpy(lpLCData, ret.c_str(), len);
			return 1;
		}
	}

	int WIN_FUNC GetLocaleInfoW(unsigned int Locale, int LCType, LPWSTR lpLCData, int cchData) {
		DEBUG_LOG("GetLocaleInfoW %d %d\n", Locale, LCType);
		std::string info = str_for_LCType(LCType);
		auto ret = stringToWideString(info.c_str());
		size_t len = ret.size();

		if (!cchData) {
			return len;
		} else {
			assert(len <= (size_t) cchData);
			memcpy(lpLCData, ret.data(), len * sizeof(*ret.data()));
			return 1;
		}
	}

	int WIN_FUNC EnumSystemLocalesA(void (*callback)(char *lpLocaleString), int dwFlags) {
		DEBUG_LOG("EnumSystemLocalesA %p %i\n", callback, dwFlags);
		// e.g. something like:
		// callback("en_US");
		// callback("ja_JP");
		return 1;
	}

	int WIN_FUNC GetUserDefaultLCID() {
		DEBUG_LOG("GetUserDefaultLCID\n");
		return 1;
	}

	BOOL WIN_FUNC IsDBCSLeadByte(BYTE TestChar) {
		DEBUG_LOG("IsDBCSLeadByte(%u)\n", TestChar);
		return FALSE; // We're not multibyte (yet?)
	}

	BOOL WIN_FUNC IsDBCSLeadByteEx(unsigned int CodePage, BYTE TestChar) {
		DEBUG_LOG("IsDBCSLeadByteEx(cp=%u, ch=%u)\n", CodePage, TestChar);

		const auto inRanges = [TestChar](std::initializer_list<std::pair<uint8_t, uint8_t>> ranges) -> BOOL {
			for (const auto &range : ranges) {
				if (TestChar >= range.first && TestChar <= range.second) {
					return TRUE;
				}
			}
			return FALSE;
		};

		constexpr unsigned int CP_ACP = 0;
		constexpr unsigned int CP_OEMCP = 1;
		constexpr unsigned int CP_MACCP = 2;
		constexpr unsigned int CP_THREAD_ACP = 3;

		if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_MACCP || CodePage == CP_THREAD_ACP) {
			return FALSE;
		}

		switch (CodePage) {
		case 932: // Japanese Shift-JIS
			return inRanges({{0x81, 0x9F}, {0xE0, 0xFC}});
		case 936: // Simplified Chinese (GBK)
		case 949: // Korean
		case 950: // Traditional Chinese (Big5)
		case 1361: // Johab
			return inRanges({{0x81, 0xFE}});
		default:
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
	}

	constexpr unsigned int LCMAP_LOWERCASE = 0x00000100;
	constexpr unsigned int LCMAP_UPPERCASE = 0x00000200;
	constexpr unsigned int LCMAP_SORTKEY = 0x00000400;
	constexpr unsigned int LCMAP_BYTEREV = 0x00000800;
	constexpr unsigned int LCMAP_LINGUISTIC_CASING = 0x01000000;

	int WIN_FUNC LCMapStringW(int Locale, unsigned int dwMapFlags, const uint16_t* lpSrcStr, int cchSrc, uint16_t* lpDestStr, int cchDest) {
		DEBUG_LOG("LCMapStringW(locale=%i, flags=0x%x, src=%p, dest=%p, cchSrc=%d, cchDest=%d)\n", Locale, dwMapFlags, lpSrcStr, lpDestStr, cchSrc, cchDest);
		(void) Locale;
		if (!lpSrcStr || cchSrc == 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		bool nullTerminated = cchSrc < 0;
		size_t srcLen = nullTerminated ? (wstrlen(lpSrcStr) + 1) : static_cast<size_t>(cchSrc);
		if (srcLen == 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		if (!lpDestStr || cchDest == 0) {
			// Caller is asking for the required length.
			wibo::lastError = ERROR_SUCCESS;
			return static_cast<int>(srcLen);
		}
		if (cchDest < static_cast<int>(srcLen)) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}

		unsigned int casingFlags = dwMapFlags & (LCMAP_UPPERCASE | LCMAP_LOWERCASE);
		unsigned int ignoredFlags = dwMapFlags & (LCMAP_LINGUISTIC_CASING);
		(void) ignoredFlags;
		if (dwMapFlags & (LCMAP_SORTKEY | LCMAP_BYTEREV)) {
			DEBUG_LOG("LCMapStringW: unsupported mapping flags 0x%x\n", dwMapFlags);
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}

		std::vector<uint16_t> buffer(srcLen, 0);
		for (size_t i = 0; i < srcLen; ++i) {
			uint16_t ch = lpSrcStr[i];
			if (casingFlags == LCMAP_UPPERCASE) {
				buffer[i] = static_cast<uint16_t>(std::towupper(static_cast<wint_t>(ch)));
			} else if (casingFlags == LCMAP_LOWERCASE) {
				buffer[i] = static_cast<uint16_t>(std::towlower(static_cast<wint_t>(ch)));
			} else {
				buffer[i] = ch;
			}
		}

		std::memcpy(lpDestStr, buffer.data(), srcLen * sizeof(uint16_t));
		wibo::lastError = ERROR_SUCCESS;
		return static_cast<int>(srcLen);
	}

	int WIN_FUNC LCMapStringA(int Locale, unsigned int dwMapFlags, const char* lpSrcStr, int cchSrc, char* lpDestStr, int cchDest) {
		DEBUG_LOG("LCMapStringA: (locale=%i, flags=%u, src=%p, dest=%p)\n", Locale, dwMapFlags, cchSrc, cchDest);
		if (cchSrc < 0) {
			cchSrc = strlen(lpSrcStr) + 1;
		}
		// DEBUG_LOG("lpSrcStr: %s\n", lpSrcStr);
		return 0; // fail
	}


	static std::string convertEnvValueForWindows(const std::string &name, const char *rawValue) {
		if (!rawValue) {
			return std::string();
		}
		if (strcasecmp(name.c_str(), "PATH") != 0) {
			return rawValue;
		}
		std::string converted = files::hostPathListToWindows(rawValue);
		return converted.empty() ? std::string(rawValue) : converted;
	}

	static std::string convertEnvValueToHost(const std::string &name, const char *rawValue) {
		if (!rawValue) {
			return std::string();
		}
		if (strcasecmp(name.c_str(), "PATH") != 0) {
			return rawValue;
		}
		std::string converted = files::windowsPathListToHost(rawValue);
		return converted.empty() ? std::string(rawValue) : converted;
	}

	DWORD WIN_FUNC GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
		DEBUG_LOG("GetEnvironmentVariableA: %s\n", lpName);
		if (!lpName) {
			return 0;
		}
		const char *rawValue = getenv(lpName);
		if (!rawValue) {
			return 0;
		}
		std::string converted = convertEnvValueForWindows(lpName, rawValue);
		const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
		unsigned int len = finalValue.size();
		if (nSize == 0) {
			return len + 1;
		}
		if (nSize <= len) {
			return len;
		}
		memcpy(lpBuffer, finalValue.c_str(), len + 1);
		return len;
	}

	BOOL WIN_FUNC SetEnvironmentVariableA(const char *lpName, const char *lpValue) {
		DEBUG_LOG("SetEnvironmentVariableA: %s=%s\n", lpName ? lpName : "(null)", lpValue ? lpValue : "(null)");
		if (!lpName || std::strchr(lpName, '=')) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		int rc = 0;
		if (!lpValue) {
			rc = unsetenv(lpName);
			if (rc != 0) {
				setLastErrorFromErrno();
				return FALSE;
			}
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		std::string hostValue = convertEnvValueToHost(lpName, lpValue);
		const char *valuePtr = hostValue.empty() ? lpValue : hostValue.c_str();
		rc = setenv(lpName, valuePtr, 1 /* overwrite */);
		if (rc != 0) {
			setLastErrorFromErrno();
			return FALSE;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	DWORD WIN_FUNC GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
		std::string name = wideStringToString(lpName);
		DEBUG_LOG("GetEnvironmentVariableW: %s\n", name.c_str());
		const char *rawValue = getenv(name.c_str());
		if (!rawValue) {
			return 0;
		}
		std::string converted = convertEnvValueForWindows(name, rawValue);
		const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
		auto wideValue = stringToWideString(finalValue.c_str());
		const auto len = wideValue.size();
		if (nSize < len) {
			return len;
		}
		wstrncpy(lpBuffer, wideValue.data(), len);
		return len - 1;
	}

	BOOL WIN_FUNC SetEnvironmentVariableW(const uint16_t *lpName, const uint16_t *lpValue) {
		if (!lpName) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		std::string name = wideStringToString(lpName);
		std::string value = lpValue ? wideStringToString(lpValue) : std::string();
		return SetEnvironmentVariableA(name.c_str(), lpValue ? value.c_str() : nullptr);
	}

	unsigned int WIN_FUNC QueryPerformanceCounter(unsigned long int *lpPerformanceCount) {
		DEBUG_LOG("QueryPerformanceCounter\n");
		*lpPerformanceCount = 0;
		return 1;
	}

	int WIN_FUNC QueryPerformanceFrequency(uint64_t *lpFrequency) {
		*lpFrequency = 1;
		return 1;
	}

	unsigned int WIN_FUNC IsDebuggerPresent() {
		DEBUG_LOG("IsDebuggerPresent\n");
		// If the current process is not running in the context of a debugger, the return value is zero.
		return 0;
	}

	void *WIN_FUNC SetUnhandledExceptionFilter(void *lpTopLevelExceptionFilter) {
		DEBUG_LOG("SetUnhandledExceptionFilter: %p\n", lpTopLevelExceptionFilter);
		return (void *)0x100008;
	}

	unsigned int WIN_FUNC UnhandledExceptionFilter(void *ExceptionInfo) {
		DEBUG_LOG("UnhandledExceptionFilter: %p\n", ExceptionInfo);
		return 1; // EXCEPTION_EXECUTE_HANDLER
	}

	unsigned int WIN_FUNC SetErrorMode(unsigned int mode){
		DEBUG_LOG("SetErrorMode: %d\n", mode);
		return 0;
	}

	struct SINGLE_LIST_ENTRY
	{
		SINGLE_LIST_ENTRY *Next;
	};

	struct SLIST_HEADER
	{
		union
		{
			unsigned long Alignment;
			struct
			{
				SINGLE_LIST_ENTRY Next;
				int Depth;
				int Sequence;
			};
		};
	};

	void WIN_FUNC InitializeSListHead(SLIST_HEADER *ListHead) {
		DEBUG_LOG("InitializeSListHead\n");
		// All list items must be aligned on a MEMORY_ALLOCATION_ALIGNMENT boundary.
		posix_memalign((void**)&ListHead, 16, sizeof(SLIST_HEADER));
		memset(ListHead, 0, sizeof(SLIST_HEADER));
	}

	typedef struct _EXCEPTION_RECORD {
		unsigned int                    ExceptionCode;
		unsigned int                    ExceptionFlags;
		struct _EXCEPTION_RECORD *ExceptionRecord;
		void*                    ExceptionAddress;
		unsigned int                    NumberParameters;
		void*                ExceptionInformation[15];
	} EXCEPTION_RECORD;

	void WIN_FUNC RtlUnwind(void *TargetFrame, void *TargetIp, EXCEPTION_RECORD *ExceptionRecord, void *ReturnValue) {
		DEBUG_LOG("RtlUnwind %p %p %p %p\n", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
		DEBUG_LOG("WARNING: Silently returning from RtlUnwind - exception handlers and clean up code may not be run");
	}

	int WIN_FUNC InterlockedIncrement(int *Addend) {
		return *Addend += 1;
	}

	int WIN_FUNC InterlockedDecrement(int *Addend) {
		return *Addend -= 1;
	}

	int WIN_FUNC InterlockedExchange(int *Target, int Value) {
		int initial = *Target;
		*Target = Value;
		return initial;
	}

	LONG WIN_FUNC InterlockedCompareExchange(volatile LONG* destination, LONG exchange, LONG comperand){
		LONG original = *destination;
		if (original == comperand) {
			*destination = exchange;
		}
		return original;
		// return __sync_val_compare_and_swap(destination, comperand, exchange); if we want to maintain the atomic behavior
	}

	// These are effectively a copy/paste of the Tls* functions
	enum { MAX_FLS_VALUES = 100 };
	static bool flsValuesUsed[MAX_FLS_VALUES] = { false };
	static void *flsValues[MAX_FLS_VALUES];
	int WIN_FUNC FlsAlloc(void *lpCallback) {
		DEBUG_LOG("FlsAlloc (lpCallback: %x)\n", lpCallback);
		// If the function succeeds, the return value is an FLS index initialized to zero.
		for (size_t i = 0; i < MAX_FLS_VALUES; i++) {
			if (flsValuesUsed[i] == false) {
				flsValuesUsed[i] = true;
				flsValues[i] = 0;
				DEBUG_LOG("...returning %d\n", i);
				return i;
			}
		}
		DEBUG_LOG("...returning nothing\n");
		wibo::lastError = 1;
		return 0xFFFFFFFF; // FLS_OUT_OF_INDEXES
	}

	unsigned int WIN_FUNC FlsFree(unsigned int dwFlsIndex) {
		DEBUG_LOG("FlsFree(%u)\n", dwFlsIndex);
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			flsValuesUsed[dwFlsIndex] = false;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	void *WIN_FUNC FlsGetValue(unsigned int dwFlsIndex) {
		// DEBUG_LOG("FlsGetValue(%u)", dwFlsIndex);
		void *result = nullptr;
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			result = flsValues[dwFlsIndex];
			// See https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue
			wibo::lastError = ERROR_SUCCESS;
		} else {
			wibo::lastError = 1;
		}
		// DEBUG_LOG(" -> %p\n", result);
		return result;
	}

	unsigned int WIN_FUNC FlsSetValue(unsigned int dwFlsIndex, void *lpFlsData) {
		// DEBUG_LOG("FlsSetValue(%u, %p)\n", dwFlsIndex, lpFlsData);
		if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
			flsValues[dwFlsIndex] = lpFlsData;
			return 1;
		} else {
			wibo::lastError = 1;
			return 0;
		}
	}

	BOOL WIN_FUNC GetOverlappedResult(void *hFile, void *lpOverlapped, int *lpNumberOfBytesTransferred, BOOL bWait) {
		// DEBUG_LOG("GetOverlappedResult(%p, %p, %p, %u)\n", hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
		return 1;
	}

}

static void *resolveByName(const char *name) {
	// errhandlingapi.h
	if (strcmp(name, "GetLastError") == 0) return (void *) kernel32::GetLastError;
	if (strcmp(name, "SetLastError") == 0) return (void *) kernel32::SetLastError;
	if (strcmp(name, "IsBadReadPtr") == 0) return (void *) kernel32::IsBadReadPtr;
	if (strcmp(name, "Wow64DisableWow64FsRedirection") == 0) return (void *) kernel32::Wow64DisableWow64FsRedirection;
	if (strcmp(name, "Wow64RevertWow64FsRedirection") == 0) return (void *) kernel32::Wow64RevertWow64FsRedirection;
	if (strcmp(name, "RaiseException") == 0) return (void *) kernel32::RaiseException;
	if (strcmp(name, "AddVectoredExceptionHandler") == 0) return (void *) kernel32::AddVectoredExceptionHandler;

	// processthreadsapi.h
	if (strcmp(name, "IsProcessorFeaturePresent") == 0) return (void *) kernel32::IsProcessorFeaturePresent;
	if (strcmp(name, "GetCurrentProcess") == 0) return (void *) kernel32::GetCurrentProcess;
	if (strcmp(name, "GetCurrentProcessId") == 0) return (void *) kernel32::GetCurrentProcessId;
	if (strcmp(name, "GetCurrentThreadId") == 0) return (void *) kernel32::GetCurrentThreadId;
	if (strcmp(name, "ExitProcess") == 0) return (void *) kernel32::ExitProcess;
	if (strcmp(name, "GetExitCodeProcess") == 0) return (void *) kernel32::GetExitCodeProcess;
	if (strcmp(name, "CreateProcessW") == 0) return (void *) kernel32::CreateProcessW;
	if (strcmp(name, "CreateProcessA") == 0) return (void *) kernel32::CreateProcessA;
	if (strcmp(name, "TlsAlloc") == 0) return (void *) kernel32::TlsAlloc;
	if (strcmp(name, "TlsFree") == 0) return (void *) kernel32::TlsFree;
	if (strcmp(name, "TlsGetValue") == 0) return (void *) kernel32::TlsGetValue;
	if (strcmp(name, "TlsSetValue") == 0) return (void *) kernel32::TlsSetValue;
	if (strcmp(name, "GetStartupInfoA") == 0) return (void *) kernel32::GetStartupInfoA;
	if (strcmp(name, "GetStartupInfoW") == 0) return (void *) kernel32::GetStartupInfoW;
	if (strcmp(name, "SetThreadStackGuarantee") == 0) return (void *) kernel32::SetThreadStackGuarantee;
	if (strcmp(name, "GetCurrentThread") == 0) return (void *) kernel32::GetCurrentThread;
	if (strcmp(name, "GetThreadTimes") == 0) return (void *) kernel32::GetThreadTimes;
	if (strcmp(name, "SetThreadDescription") == 0) return (void *) kernel32::SetThreadDescription;

	// winnls.h
	if (strcmp(name, "GetSystemDefaultLangID") == 0) return (void *) kernel32::GetSystemDefaultLangID;
	if (strcmp(name, "GetUserDefaultUILanguage") == 0) return (void *) kernel32::GetUserDefaultUILanguage;
	if (strcmp(name, "GetACP") == 0) return (void *) kernel32::GetACP;
	if (strcmp(name, "GetCPInfo") == 0) return (void *) kernel32::GetCPInfo;
	if (strcmp(name, "CompareStringA") == 0) return (void *) kernel32::CompareStringA;
	if (strcmp(name, "CompareStringW") == 0) return (void *) kernel32::CompareStringW;
	if (strcmp(name, "IsValidLocale") == 0) return (void *) kernel32::IsValidLocale;
	if (strcmp(name, "IsValidCodePage") == 0) return (void *) kernel32::IsValidCodePage;
	if (strcmp(name, "LCMapStringW") == 0) return (void *) kernel32::LCMapStringW;
	if (strcmp(name, "LCMapStringA") == 0) return (void *) kernel32::LCMapStringA;
	if (strcmp(name, "GetLocaleInfoA") == 0) return (void *) kernel32::GetLocaleInfoA;
	if (strcmp(name, "GetLocaleInfoW") == 0) return (void *) kernel32::GetLocaleInfoW;
	if (strcmp(name, "EnumSystemLocalesA") == 0) return (void *) kernel32::EnumSystemLocalesA;
	if (strcmp(name, "GetUserDefaultLCID") == 0) return (void *) kernel32::GetUserDefaultLCID;
	if (strcmp(name, "IsDBCSLeadByte") == 0) return (void *) kernel32::IsDBCSLeadByte;
	if (strcmp(name, "IsDBCSLeadByteEx") == 0) return (void *) kernel32::IsDBCSLeadByteEx;

	// synchapi.h
	if (strcmp(name, "InitializeCriticalSection") == 0) return (void *) kernel32::InitializeCriticalSection;
	if (strcmp(name, "InitializeCriticalSectionEx") == 0) return (void *) kernel32::InitializeCriticalSectionEx;
	if (strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0) return (void *) kernel32::InitializeCriticalSectionAndSpinCount;
	if (strcmp(name, "DeleteCriticalSection") == 0) return (void *) kernel32::DeleteCriticalSection;
	if (strcmp(name, "EnterCriticalSection") == 0) return (void *) kernel32::EnterCriticalSection;
	if (strcmp(name, "LeaveCriticalSection") == 0) return (void *) kernel32::LeaveCriticalSection;
	if (strcmp(name, "InitOnceBeginInitialize") == 0) return (void *) kernel32::InitOnceBeginInitialize;
	if (strcmp(name, "InitOnceComplete") == 0) return (void *) kernel32::InitOnceComplete;
	if (strcmp(name, "AcquireSRWLockShared") == 0) return (void *) kernel32::AcquireSRWLockShared;
	if (strcmp(name, "ReleaseSRWLockShared") == 0) return (void *) kernel32::ReleaseSRWLockShared;
	if (strcmp(name, "AcquireSRWLockExclusive") == 0) return (void *) kernel32::AcquireSRWLockExclusive;
	if (strcmp(name, "ReleaseSRWLockExclusive") == 0) return (void *) kernel32::ReleaseSRWLockExclusive;
	if (strcmp(name, "TryAcquireSRWLockExclusive") == 0) return (void *) kernel32::TryAcquireSRWLockExclusive;
	if (strcmp(name, "WaitForSingleObject") == 0) return (void *) kernel32::WaitForSingleObject;
	if (strcmp(name, "CreateMutexW") == 0) return (void *) kernel32::CreateMutexW;
	if (strcmp(name, "ReleaseMutex") == 0) return (void *) kernel32::ReleaseMutex;

	// winbase.h
	if (strcmp(name, "GlobalAlloc") == 0) return (void *) kernel32::GlobalAlloc;
	if (strcmp(name, "GlobalReAlloc") == 0) return (void *) kernel32::GlobalReAlloc;
	if (strcmp(name, "GlobalFree") == 0) return (void *) kernel32::GlobalFree;
	if (strcmp(name, "GlobalFlags") == 0) return (void *) kernel32::GlobalFlags;
	if (strcmp(name, "GetCurrentDirectoryA") == 0) return (void *) kernel32::GetCurrentDirectoryA;
	if (strcmp(name, "GetCurrentDirectoryW") == 0) return (void *) kernel32::GetCurrentDirectoryW;
	if (strcmp(name, "FindResourceA") == 0) return (void *) kernel32::FindResourceA;
	if (strcmp(name, "FindResourceExA") == 0) return (void *) kernel32::FindResourceExA;
	if (strcmp(name, "FindResourceW") == 0) return (void *) kernel32::FindResourceW;
	if (strcmp(name, "FindResourceExW") == 0) return (void *) kernel32::FindResourceExW;
	if (strcmp(name, "SetHandleCount") == 0) return (void *) kernel32::SetHandleCount;
	if (strcmp(name, "FormatMessageA") == 0) return (void *) kernel32::FormatMessageA;
	if (strcmp(name, "GetComputerNameA") == 0) return (void *) kernel32::GetComputerNameA;
	if (strcmp(name, "GetComputerNameW") == 0) return (void *) kernel32::GetComputerNameW;
	if (strcmp(name, "EncodePointer") == 0) return (void *) kernel32::EncodePointer;
	if (strcmp(name, "DecodePointer") == 0) return (void *) kernel32::DecodePointer;
	if (strcmp(name, "SetDllDirectoryA") == 0) return (void *) kernel32::SetDllDirectoryA;
	if (strcmp(name, "Sleep") == 0) return (void *) kernel32::Sleep;
	if (strcmp(name, "VirtualProtect") == 0) return (void *) kernel32::VirtualProtect;
	if (strcmp(name, "VirtualQuery") == 0) return (void *) kernel32::VirtualQuery;

	// processenv.h
	if (strcmp(name, "GetCommandLineA") == 0) return (void *) kernel32::GetCommandLineA;
	if (strcmp(name, "GetCommandLineW") == 0) return (void *) kernel32::GetCommandLineW;
	if (strcmp(name, "GetEnvironmentStrings") == 0) return (void *) kernel32::GetEnvironmentStrings;
	if (strcmp(name, "FreeEnvironmentStringsA") == 0) return (void *) kernel32::FreeEnvironmentStringsA;
	if (strcmp(name, "GetEnvironmentStringsW") == 0) return (void *) kernel32::GetEnvironmentStringsW;
	if (strcmp(name, "FreeEnvironmentStringsW") == 0) return (void *) kernel32::FreeEnvironmentStringsW;
	if (strcmp(name, "GetEnvironmentVariableA") == 0) return (void *) kernel32::GetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableA") == 0) return (void *) kernel32::SetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableW") == 0) return (void *) kernel32::SetEnvironmentVariableW;
	if (strcmp(name, "GetEnvironmentVariableW") == 0) return (void *) kernel32::GetEnvironmentVariableW;

	// console api
	if (strcmp(name, "GetStdHandle") == 0) return (void *) kernel32::GetStdHandle;
	if (strcmp(name, "SetStdHandle") == 0) return (void *) kernel32::SetStdHandle;
	if (strcmp(name, "DuplicateHandle") == 0) return (void *) kernel32::DuplicateHandle;
	if (strcmp(name, "CloseHandle") == 0) return (void *) kernel32::CloseHandle;
	if (strcmp(name, "GetConsoleMode") == 0) return (void *) kernel32::GetConsoleMode;
	if (strcmp(name, "SetConsoleCtrlHandler") == 0) return (void *) kernel32::SetConsoleCtrlHandler;
	if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) return (void *) kernel32::GetConsoleScreenBufferInfo;
	if (strcmp(name, "WriteConsoleW") == 0) return (void *) kernel32::WriteConsoleW;
	if (strcmp(name, "GetConsoleOutputCP") == 0) return (void *) kernel32::GetConsoleOutputCP;

	// fileapi.h
	if (strcmp(name, "GetFullPathNameA") == 0) return (void *) kernel32::GetFullPathNameA;
	if (strcmp(name, "GetFullPathNameW") == 0) return (void *) kernel32::GetFullPathNameW;
	if (strcmp(name, "GetShortPathNameA") == 0) return (void *) kernel32::GetShortPathNameA;
	if (strcmp(name, "GetShortPathNameW") == 0) return (void *) kernel32::GetShortPathNameW;
	if (strcmp(name, "FindFirstFileA") == 0) return (void *) kernel32::FindFirstFileA;
	if (strcmp(name, "FindFirstFileW") == 0) return (void *) kernel32::FindFirstFileW;
	if (strcmp(name, "FindFirstFileExA") == 0) return (void *) kernel32::FindFirstFileExA;
	if (strcmp(name, "FindNextFileA") == 0) return (void *) kernel32::FindNextFileA;
	if (strcmp(name, "FindClose") == 0) return (void *) kernel32::FindClose;
	if (strcmp(name, "GetFileAttributesA") == 0) return (void *) kernel32::GetFileAttributesA;
	if (strcmp(name, "GetFileAttributesW") == 0) return (void *) kernel32::GetFileAttributesW;
	if (strcmp(name, "WriteFile") == 0) return (void *) kernel32::WriteFile;
	if (strcmp(name, "ReadFile") == 0) return (void *) kernel32::ReadFile;
	if (strcmp(name, "CreateFileA") == 0) return (void *) kernel32::CreateFileA;
	if (strcmp(name, "CreateFileW") == 0) return (void *) kernel32::CreateFileW;
	if (strcmp(name, "CreateFileMappingA") == 0) return (void *) kernel32::CreateFileMappingA;
	if (strcmp(name, "CreateFileMappingW") == 0) return (void *) kernel32::CreateFileMappingW;
	if (strcmp(name, "MapViewOfFile") == 0) return (void *) kernel32::MapViewOfFile;
	if (strcmp(name, "UnmapViewOfFile") == 0) return (void *) kernel32::UnmapViewOfFile;
	if (strcmp(name, "DeleteFileA") == 0) return (void *) kernel32::DeleteFileA;
	if (strcmp(name, "DeleteFileW") == 0) return (void *) kernel32::DeleteFileW;
	if (strcmp(name, "SetFilePointer") == 0) return (void *) kernel32::SetFilePointer;
	if (strcmp(name, "SetFilePointerEx") == 0) return (void *) kernel32::SetFilePointerEx;
	if (strcmp(name, "SetEndOfFile") == 0) return (void *) kernel32::SetEndOfFile;
	if (strcmp(name, "CreateDirectoryA") == 0) return (void *) kernel32::CreateDirectoryA;
	if (strcmp(name, "RemoveDirectoryA") == 0) return (void *) kernel32::RemoveDirectoryA;
	if (strcmp(name, "SetFileAttributesA") == 0) return (void *) kernel32::SetFileAttributesA;
	if (strcmp(name, "GetFileSize") == 0) return (void *) kernel32::GetFileSize;
	if (strcmp(name, "GetFileTime") == 0) return (void *) kernel32::GetFileTime;
	if (strcmp(name, "SetFileTime") == 0) return (void *) kernel32::SetFileTime;
	if (strcmp(name, "GetFileType") == 0) return (void *) kernel32::GetFileType;
	if (strcmp(name, "FileTimeToLocalFileTime") == 0) return (void *) kernel32::FileTimeToLocalFileTime;
	if (strcmp(name, "GetFileInformationByHandle") == 0) return (void *) kernel32::GetFileInformationByHandle;
	if (strcmp(name, "GetTempFileNameA") == 0) return (void *) kernel32::GetTempFileNameA;
	if (strcmp(name, "GetTempPathA") == 0) return (void *) kernel32::GetTempPathA;
	if (strcmp(name, "GetDiskFreeSpaceExW") == 0) return (void*) kernel32::GetDiskFreeSpaceExW;

	// sysinfoapi.h
	if (strcmp(name, "GetSystemInfo") == 0) return (void *) kernel32::GetSystemInfo;
	if (strcmp(name, "GetSystemTime") == 0) return (void *) kernel32::GetSystemTime;
	if (strcmp(name, "GetLocalTime") == 0) return (void *) kernel32::GetLocalTime;
	if (strcmp(name, "GetSystemTimeAsFileTime") == 0) return (void *) kernel32::GetSystemTimeAsFileTime;
	if (strcmp(name, "GetTickCount") == 0) return (void *) kernel32::GetTickCount;
	if (strcmp(name, "GetSystemDirectoryA") == 0) return (void *) kernel32::GetSystemDirectoryA;
	if (strcmp(name, "GetWindowsDirectoryA") == 0) return (void *) kernel32::GetWindowsDirectoryA;
	if (strcmp(name, "GetVersion") == 0) return (void *) kernel32::GetVersion;
	if (strcmp(name, "GetVersionExA") == 0) return (void *) kernel32::GetVersionExA;

	// timezoneapi.h
	if (strcmp(name, "SystemTimeToFileTime") == 0) return (void *) kernel32::SystemTimeToFileTime;
	if (strcmp(name, "FileTimeToSystemTime") == 0) return (void *) kernel32::FileTimeToSystemTime;
	if (strcmp(name, "GetTimeZoneInformation") == 0) return (void *) kernel32::GetTimeZoneInformation;

	// libloaderapi.h
	if (strcmp(name, "GetModuleHandleA") == 0) return (void *) kernel32::GetModuleHandleA;
	if (strcmp(name, "GetModuleHandleW") == 0) return (void *) kernel32::GetModuleHandleW;
	if (strcmp(name, "GetModuleFileNameA") == 0) return (void *) kernel32::GetModuleFileNameA;
	if (strcmp(name, "GetModuleFileNameW") == 0) return (void *) kernel32::GetModuleFileNameW;
	if (strcmp(name, "LoadResource") == 0) return (void *) kernel32::LoadResource;
	if (strcmp(name, "LockResource") == 0) return (void *) kernel32::LockResource;
	if (strcmp(name, "SizeofResource") == 0) return (void *) kernel32::SizeofResource;
	if (strcmp(name, "LoadLibraryA") == 0) return (void *) kernel32::LoadLibraryA;
	if (strcmp(name, "LoadLibraryW") == 0) return (void *) kernel32::LoadLibraryW;
	if (strcmp(name, "LoadLibraryExW") == 0) return (void *) kernel32::LoadLibraryExW;
	if (strcmp(name, "DisableThreadLibraryCalls") == 0) return (void *) kernel32::DisableThreadLibraryCalls;
	if (strcmp(name, "FreeLibrary") == 0) return (void *) kernel32::FreeLibrary;
	if (strcmp(name, "GetProcAddress") == 0) return (void *) kernel32::GetProcAddress;

	// heapapi.h
	if (strcmp(name, "HeapCreate") == 0) return (void *) kernel32::HeapCreate;
	if (strcmp(name, "GetProcessHeap") == 0) return (void *) kernel32::GetProcessHeap;
	if (strcmp(name, "HeapSetInformation") == 0) return (void *) kernel32::HeapSetInformation;
	if (strcmp(name, "HeapAlloc") == 0) return (void *) kernel32::HeapAlloc;
	if (strcmp(name, "HeapReAlloc") == 0) return (void *) kernel32::HeapReAlloc;
	if (strcmp(name, "HeapSize") == 0) return (void *) kernel32::HeapSize;
	if (strcmp(name, "HeapFree") == 0) return (void *) kernel32::HeapFree;

	// memoryapi.h
	if (strcmp(name, "VirtualAlloc") == 0) return (void *) kernel32::VirtualAlloc;
	if (strcmp(name, "VirtualFree") == 0) return (void *) kernel32::VirtualFree;
	if (strcmp(name, "GetProcessWorkingSetSize") == 0) return (void *) kernel32::GetProcessWorkingSetSize;
	if (strcmp(name, "SetProcessWorkingSetSize") == 0) return (void *) kernel32::SetProcessWorkingSetSize;

	// stringapiset.h
	if (strcmp(name, "WideCharToMultiByte") == 0) return (void *) kernel32::WideCharToMultiByte;
	if (strcmp(name, "MultiByteToWideChar") == 0) return (void *) kernel32::MultiByteToWideChar;
	if (strcmp(name, "GetStringTypeW") == 0) return (void *) kernel32::GetStringTypeW;

	// profileapi.h
	if (strcmp(name, "QueryPerformanceCounter") == 0) return (void *) kernel32::QueryPerformanceCounter;
	if (strcmp(name, "QueryPerformanceFrequency") == 0) return (void *) kernel32::QueryPerformanceFrequency;

	// debugapi.h
	if (strcmp(name, "IsDebuggerPresent") == 0) return (void *) kernel32::IsDebuggerPresent;

	// errhandlingapi.h
	if (strcmp(name, "SetUnhandledExceptionFilter") == 0) return (void *) kernel32::SetUnhandledExceptionFilter;
	if (strcmp(name, "UnhandledExceptionFilter") == 0) return (void *) kernel32::UnhandledExceptionFilter;
	if (strcmp(name, "SetErrorMode") == 0) return (void*)kernel32::SetErrorMode;

	// interlockedapi.h
	if (strcmp(name, "InitializeSListHead") == 0) return (void *) kernel32::InitializeSListHead;

	// winnt.h
	if (strcmp(name, "RtlUnwind") == 0) return (void *) kernel32::RtlUnwind;
	if (strcmp(name, "InterlockedIncrement") == 0) return (void *) kernel32::InterlockedIncrement;
	if (strcmp(name, "InterlockedDecrement") == 0) return (void *) kernel32::InterlockedDecrement;
	if (strcmp(name, "InterlockedExchange") == 0) return (void *) kernel32::InterlockedExchange;
	if (strcmp(name, "InterlockedCompareExchange") == 0) return (void*) kernel32::InterlockedCompareExchange;

	// fibersapi.h
	if (strcmp(name, "FlsAlloc") == 0) return (void *) kernel32::FlsAlloc;
	if (strcmp(name, "FlsFree") == 0) return (void *) kernel32::FlsFree;
	if (strcmp(name, "FlsSetValue") == 0) return (void *) kernel32::FlsSetValue;
	if (strcmp(name, "FlsGetValue") == 0) return (void *) kernel32::FlsGetValue;

	// ioapiset.h
	if (strcmp(name, "GetOverlappedResult") == 0) return (void *) kernel32::GetOverlappedResult;

	return 0;
}

wibo::Module lib_kernel32 = {
	(const char *[]){
		"kernel32",
		"kernel32.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
