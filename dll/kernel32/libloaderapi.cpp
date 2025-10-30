#include "libloaderapi.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "modules.h"
#include "resources.h"
#include "strutil.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <optional>
#include <string>

namespace {

HRSRC findResourceInternal(HMODULE hModule, const wibo::ResourceIdentifier &type, const wibo::ResourceIdentifier &name,
						   std::optional<uint16_t> language) {
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe) {
		kernel32::setLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return nullptr;
	}
	wibo::ResourceLocation loc;
	if (!exe->findResource(type, name, language, loc)) {
		return nullptr;
	}
	return reinterpret_cast<HRSRC>(const_cast<void *>(loc.dataEntry));
}

} // namespace

namespace kernel32 {

BOOL WINAPI DisableThreadLibraryCalls(HMODULE hLibModule) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DisableThreadLibraryCalls(%p)\n", hLibModule);
	if (!hLibModule) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	wibo::ModuleInfo *info = wibo::moduleInfoFromHandle(hLibModule);
	if (!info) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (!wibo::disableThreadNotifications(info)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return TRUE;
}

HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleHandleA(%s)\n", lpModuleName);
	const auto *module = wibo::findLoadedModule(lpModuleName);
	if (!module) {
		setLastError(ERROR_MOD_NOT_FOUND);
		return nullptr;
	}
	return module->handle;
}

HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleHandleW -> ");
	if (lpModuleName) {
		const auto lpModuleNameA = wideStringToString(lpModuleName);
		return GetModuleHandleA(lpModuleNameA.c_str());
	}
	return GetModuleHandleA(nullptr);
}

DWORD WINAPI GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleFileNameA(%p, %p, %u)\n", hModule, lpFilename, nSize);
	if (!lpFilename) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	auto *info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string path;
	if (!info->resolvedPath.empty()) {
		path = files::pathToWindows(info->resolvedPath);
	} else {
		path = info->originalName;
	}
	DEBUG_LOG("-> %s\n", path.c_str());
	if (nSize == 0) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	const size_t len = path.size();
	const size_t copyLen = std::min(len, static_cast<size_t>(nSize - 1));
	std::memcpy(lpFilename, path.c_str(), copyLen);
	if (copyLen < nSize) {
		lpFilename[copyLen] = '\0';
	}
	if (copyLen < len) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return nSize;
	}
	return static_cast<DWORD>(copyLen);
}

DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleFileNameW(%p, %s, %u)\n", hModule, wideStringToString(lpFilename).c_str(), nSize);
	if (!lpFilename) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	auto *info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string path;
	if (!info->resolvedPath.empty()) {
		path = files::pathToWindows(info->resolvedPath);
	} else {
		path = info->originalName;
	}
	if (nSize == 0) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	auto wide = stringToWideString(path.c_str());
	if (wide.empty()) {
		wide.push_back(0);
	}
	const size_t len = wide.size() - 1;
	const size_t copyLen = std::min(len, static_cast<size_t>(nSize - 1));
	for (size_t i = 0; i < copyLen; ++i) {
		lpFilename[i] = wide[i];
	}
	if (copyLen < static_cast<size_t>(nSize)) {
		lpFilename[copyLen] = 0;
	}
	if (copyLen < len) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return nSize;
	}
	return static_cast<DWORD>(copyLen);
}

HRSRC WINAPI FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceA %p %p %p\n", hModule, lpName, lpType);
	auto type = wibo::resourceIdentifierFromAnsi(lpType);
	auto name = wibo::resourceIdentifierFromAnsi(lpName);
	return findResourceInternal(hModule, type, name, std::nullopt);
}

HRSRC WINAPI FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceExA %p %p %p %u\n", hModule, lpName, lpType, wLanguage);
	auto type = wibo::resourceIdentifierFromAnsi(lpType);
	auto name = wibo::resourceIdentifierFromAnsi(lpName);
	return findResourceInternal(hModule, type, name, wLanguage);
}

HRSRC WINAPI FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceW %p\n", hModule);
	auto type = wibo::resourceIdentifierFromWide(lpType);
	auto name = wibo::resourceIdentifierFromWide(lpName);
	return findResourceInternal(hModule, type, name, std::nullopt);
}

HRSRC WINAPI FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceExW %p %u\n", hModule, wLanguage);
	auto type = wibo::resourceIdentifierFromWide(lpType);
	auto name = wibo::resourceIdentifierFromWide(lpName);
	return findResourceInternal(hModule, type, name, wLanguage);
}

HGLOBAL WINAPI LoadResource(HMODULE hModule, HRSRC hResInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadResource %p %p\n", hModule, hResInfo);
	if (!hResInfo) {
		setLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return nullptr;
	}
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe || !exe->rsrcBase) {
		setLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return nullptr;
	}
	const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(hResInfo);
	if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
		setLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	return const_cast<void *>(exe->fromRVA<const void>(entry->offsetToData));
}

LPVOID WINAPI LockResource(HGLOBAL hResData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LockResource(%p)\n", hResData);
	return hResData;
}

DWORD WINAPI SizeofResource(HMODULE hModule, HRSRC hResInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SizeofResource(%p, %p)\n", hModule, hResInfo);
	if (!hResInfo) {
		setLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return 0;
	}
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe || !exe->rsrcBase) {
		setLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return 0;
	}
	const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(hResInfo);
	if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	return entry->size;
}

HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadLibraryA(%s)\n", lpLibFileName);
	const auto *info = wibo::loadModule(lpLibFileName);
	if (!info) {
		// lastError is set by loadModule
		return nullptr;
	}
	return info->handle;
}

HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName) {
	HOST_CONTEXT_GUARD();
	if (!lpLibFileName) {
		return nullptr;
	}
	auto filename = wideStringToString(lpLibFileName);
	DEBUG_LOG("LoadLibraryW(%s)\n", filename.c_str());
	return LoadLibraryA(filename.c_str());
}

HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	(void)hFile;
	// TOOD: handle dwFlags properly
	DEBUG_LOG("LoadLibraryExW(%x) -> ", dwFlags);
	auto filename = wideStringToString(lpLibFileName);
	return LoadLibraryA(filename.c_str());
}

BOOL WINAPI FreeLibrary(HMODULE hLibModule) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FreeLibrary(%p)\n", hLibModule);
	auto *info = wibo::moduleInfoFromHandle(hLibModule);
	if (!info) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	wibo::freeModule(info);
	return TRUE;
}

FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	HOST_CONTEXT_GUARD();
	FARPROC result;
	const auto info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		DEBUG_LOG("GetProcAddress(%p) -> ERROR_INVALID_HANDLE\n", hModule);
		setLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	const auto proc = reinterpret_cast<uintptr_t>(lpProcName);
	if (proc & ~0xFFFFu) {
		DEBUG_LOG("GetProcAddress(%s, %s) ", info->normalizedName.c_str(), lpProcName);
		result = wibo::resolveFuncByName(info, lpProcName);
	} else {
		DEBUG_LOG("GetProcAddress(%s, %u) ", info->normalizedName.c_str(), proc);
		result = wibo::resolveFuncByOrdinal(info, static_cast<uint16_t>(proc));
	}
	DEBUG_LOG("-> %p\n", result);
	if (!result) {
		setLastError(ERROR_PROC_NOT_FOUND);
	}
	return result;
}

} // namespace kernel32
