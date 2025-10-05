#include "libloaderapi.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "modules.h"
#include "resources.h"
#include "strutil.h"

#include <algorithm>
#include <cassert>
#include <optional>
#include <string>

namespace {

HRSRC findResourceInternal(HMODULE hModule, const wibo::ResourceIdentifier &type, const wibo::ResourceIdentifier &name,
						   std::optional<uint16_t> language) {
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
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

BOOL WIN_FUNC DisableThreadLibraryCalls(HMODULE hLibModule) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DisableThreadLibraryCalls(%p)\n", hLibModule);
	if (!hLibModule) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::ModuleInfo *info = wibo::moduleInfoFromHandle(hLibModule);
	if (!info) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (!wibo::disableThreadNotifications(info)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

HMODULE WIN_FUNC GetModuleHandleA(LPCSTR lpModuleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleHandleA(%s)\n", lpModuleName);
	const auto *module = wibo::findLoadedModule(lpModuleName);
	if (!module) {
		wibo::lastError = ERROR_MOD_NOT_FOUND;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return module->handle;
}

HMODULE WIN_FUNC GetModuleHandleW(LPCWSTR lpModuleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleHandleW -> ");
	if (lpModuleName) {
		const auto lpModuleNameA = wideStringToString(lpModuleName);
		return GetModuleHandleA(lpModuleNameA.c_str());
	}
	return GetModuleHandleA(nullptr);
}

DWORD WIN_FUNC GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleFileNameA(%p, %p, %u)\n", hModule, lpFilename, nSize);
	if (!lpFilename) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	auto *info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
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
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return 0;
	}
	const size_t len = path.size();
	const size_t copyLen = std::min(len, static_cast<size_t>(nSize - 1));
	std::memcpy(lpFilename, path.c_str(), copyLen);
	if (copyLen < nSize) {
		lpFilename[copyLen] = '\0';
	}
	if (copyLen < len) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return nSize;
	}
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(copyLen);
}

DWORD WIN_FUNC GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetModuleFileNameW(%p, %s, %u)\n", hModule, wideStringToString(lpFilename).c_str(), nSize);
	if (!lpFilename) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	auto *info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string path;
	if (!info->resolvedPath.empty()) {
		path = files::pathToWindows(info->resolvedPath);
	} else {
		path = info->originalName;
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
	for (size_t i = 0; i < copyLen; ++i) {
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
	return static_cast<DWORD>(copyLen);
}

HRSRC WIN_FUNC FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceA %p %p %p\n", hModule, lpName, lpType);
	auto type = wibo::resourceIdentifierFromAnsi(lpType);
	auto name = wibo::resourceIdentifierFromAnsi(lpName);
	return findResourceInternal(hModule, type, name, std::nullopt);
}

HRSRC WIN_FUNC FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceExA %p %p %p %u\n", hModule, lpName, lpType, wLanguage);
	auto type = wibo::resourceIdentifierFromAnsi(lpType);
	auto name = wibo::resourceIdentifierFromAnsi(lpName);
	return findResourceInternal(hModule, type, name, wLanguage);
}

HRSRC WIN_FUNC FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceW %p\n", hModule);
	auto type = wibo::resourceIdentifierFromWide(lpType);
	auto name = wibo::resourceIdentifierFromWide(lpName);
	return findResourceInternal(hModule, type, name, std::nullopt);
}

HRSRC WIN_FUNC FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindResourceExW %p %u\n", hModule, wLanguage);
	auto type = wibo::resourceIdentifierFromWide(lpType);
	auto name = wibo::resourceIdentifierFromWide(lpName);
	return findResourceInternal(hModule, type, name, wLanguage);
}

HGLOBAL WIN_FUNC LoadResource(HMODULE hModule, HRSRC hResInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadResource %p %p\n", hModule, hResInfo);
	if (!hResInfo) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return nullptr;
	}
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe || !exe->rsrcBase) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return nullptr;
	}
	const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(hResInfo);
	if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	return const_cast<void *>(exe->fromRVA<const void>(entry->offsetToData));
}

LPVOID WIN_FUNC LockResource(HGLOBAL hResData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LockResource(%p)\n", hResData);
	return hResData;
}

DWORD WIN_FUNC SizeofResource(HMODULE hModule, HRSRC hResInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SizeofResource(%p, %p)\n", hModule, hResInfo);
	if (!hResInfo) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return 0;
	}
	auto *exe = wibo::executableFromModule(hModule);
	if (!exe || !exe->rsrcBase) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return 0;
	}
	const auto *entry = reinterpret_cast<const wibo::ImageResourceDataEntry *>(hResInfo);
	if (!wibo::resourceEntryBelongsToExecutable(*exe, entry)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	return entry->size;
}

HMODULE WIN_FUNC LoadLibraryA(LPCSTR lpLibFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadLibraryA(%s)\n", lpLibFileName);
	const auto *info = wibo::loadModule(lpLibFileName);
	if (!info) {
		// lastError is set by loadModule
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return info->handle;
}

HMODULE WIN_FUNC LoadLibraryW(LPCWSTR lpLibFileName) {
	HOST_CONTEXT_GUARD();
	if (!lpLibFileName) {
		return nullptr;
	}
	auto filename = wideStringToString(lpLibFileName);
	DEBUG_LOG("LoadLibraryW(%s)\n", filename.c_str());
	return LoadLibraryA(filename.c_str());
}

HMODULE WIN_FUNC LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	assert(!hFile);
	DEBUG_LOG("LoadLibraryExW(%x) -> ", dwFlags);
	auto filename = wideStringToString(lpLibFileName);
	return LoadLibraryA(filename.c_str());
}

BOOL WIN_FUNC FreeLibrary(HMODULE hLibModule) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FreeLibrary(%p)\n", hLibModule);
	auto *info = wibo::moduleInfoFromHandle(hLibModule);
	if (!info) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::freeModule(info);
	return TRUE;
}

FARPROC WIN_FUNC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	HOST_CONTEXT_GUARD();
	FARPROC result;
	const auto info = wibo::moduleInfoFromHandle(hModule);
	if (!info) {
		DEBUG_LOG("GetProcAddress(%p) -> ERROR_INVALID_HANDLE\n", hModule);
		wibo::lastError = ERROR_INVALID_HANDLE;
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
		wibo::lastError = ERROR_PROC_NOT_FOUND;
	} else {
		wibo::lastError = ERROR_SUCCESS;
	}
	return result;
}

} // namespace kernel32
