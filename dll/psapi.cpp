#include "psapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "kernel32/internal.h"
#include "modules.h"

#include <algorithm>
#include <cstring>
#include <sys/resource.h>
#include <unistd.h>

namespace {

bool isCurrentProcessHandle(HANDLE hProcess) { return kernel32::isPseudoCurrentProcessHandle(hProcess); }

wibo::ModuleInfo *moduleForHandleOrMain(HMODULE hModule) {
	if (hModule == NO_HANDLE) {
		return wibo::mainModule;
	}
	return wibo::moduleInfoFromHandle(hModule);
}

} // namespace

namespace psapi {

BOOL WINAPI EnumProcessModules(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("EnumProcessModules(%p, %p, %u, %p)\n", hProcess, lphModule, cb, lpcbNeeded);
	if (!isCurrentProcessHandle(hProcess) || !lpcbNeeded) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*lpcbNeeded = sizeof(HMODULE);
	if (lphModule && cb >= sizeof(HMODULE)) {
		*lphModule = wibo::mainModule ? wibo::mainModule->handle : NO_HANDLE;
	}
	return TRUE;
}

DWORD WINAPI GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleFileNameExA(%p, %p, %p, %u)\n", hProcess, hModule, lpFilename, nSize);
	if (!isCurrentProcessHandle(hProcess) || !lpFilename || nSize == 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	auto *module = moduleForHandleOrMain(hModule);
	if (!module) {
		kernel32::setLastError(ERROR_INVALID_HANDLE);
		return 0;
	}
	std::string path =
		!module->resolvedPath.empty() ? files::pathToWindows(module->resolvedPath) : module->originalName;
	size_t copyLen = std::min(path.size(), static_cast<size_t>(nSize - 1));
	std::memcpy(lpFilename, path.c_str(), copyLen);
	lpFilename[copyLen] = '\0';
	if (copyLen < path.size()) {
		kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
		return nSize;
	}
	return static_cast<DWORD>(copyLen);
}

BOOL WINAPI GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleInformation(%p, %p, %p, %u)\n", hProcess, hModule, lpmodinfo, cb);
	if (!isCurrentProcessHandle(hProcess) || !lpmodinfo || cb < sizeof(MODULEINFO)) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	auto *module = moduleForHandleOrMain(hModule);
	if (!module || !module->executable) {
		kernel32::setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	lpmodinfo->lpBaseOfDll = module->executable->imageBase;
	lpmodinfo->SizeOfImage = module->executable->imageSize;
	lpmodinfo->EntryPoint = module->executable->entryPoint;
	return TRUE;
}

BOOL WINAPI GetProcessMemoryInfo(HANDLE Process, PPROCESS_MEMORY_COUNTERS ppsmemCounters, DWORD cb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetProcessMemoryInfo(%p, %p, %u)\n", Process, ppsmemCounters, cb);
	if (!isCurrentProcessHandle(Process) || !ppsmemCounters || cb < sizeof(PROCESS_MEMORY_COUNTERS)) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	std::memset(ppsmemCounters, 0, sizeof(PROCESS_MEMORY_COUNTERS));
	ppsmemCounters->cb = sizeof(PROCESS_MEMORY_COUNTERS);

	struct rusage usage{};
	if (getrusage(RUSAGE_SELF, &usage) == 0) {
		ppsmemCounters->PeakWorkingSetSize = static_cast<SIZE_T>(usage.ru_maxrss) * 1024;
		ppsmemCounters->WorkingSetSize = ppsmemCounters->PeakWorkingSetSize;
		ppsmemCounters->PageFaultCount = static_cast<DWORD>(usage.ru_minflt + usage.ru_majflt);
	}
	return TRUE;
}

BOOL WINAPI QueryWorkingSet(HANDLE hProcess, PVOID pv, DWORD cb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("QueryWorkingSet(%p, %p, %u)\n", hProcess, pv, cb);
	if (!isCurrentProcessHandle(hProcess) || !pv || cb < sizeof(ULONG_PTR)) {
		kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}
	*static_cast<ULONG_PTR *>(pv) = 0;
	return TRUE;
}

} // namespace psapi

#include "psapi_trampolines.h"

extern const wibo::ModuleStub lib_psapi = {
	(const char *[]){
		"psapi",
		"psapi.dll",
		nullptr,
	},
	psapiThunkByName,
	nullptr,
	{},
};
