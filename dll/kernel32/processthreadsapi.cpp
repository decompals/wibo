#include "common.h"
#include "errors.h"
#include "handles.h"
#include "kernel32.h"
#include "processes.h"
#include "strutil.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {
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

DWORD_PTR g_processAffinityMask = 0;
bool g_processAffinityMaskInitialized = false;
} // namespace

namespace kernel32 {

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

} // namespace kernel32
