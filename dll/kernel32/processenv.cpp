#include "processenv.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "heap.h"
#include "internal.h"
#include "strutil.h"
#include "types.h"

#include <cstdlib>
#include <cstring>
#include <mimalloc.h>
#include <string>
#include <strings.h>
#include <unistd.h>

#ifdef __APPLE__
extern char **environ;
#endif

namespace {

GUEST_PTR g_commandLineA = GUEST_NULL;
GUEST_PTR g_commandLineW = GUEST_NULL;

std::string convertEnvValueForWindows(const std::string &name, const char *rawValue) {
	if (!rawValue) {
		return {};
	}
	if (strcasecmp(name.c_str(), "PATH") != 0) {
		return rawValue;
	}
	std::string converted = files::hostPathListToWindows(rawValue);
	return converted.empty() ? std::string(rawValue) : converted;
}

std::string convertEnvValueToHost(const std::string &name, const char *rawValue) {
	if (!rawValue) {
		return {};
	}
	if (strcasecmp(name.c_str(), "PATH") != 0) {
		return rawValue;
	}
	std::string converted = files::windowsPathListToHost(rawValue);
	return converted.empty() ? std::string(rawValue) : converted;
}

} // namespace

namespace kernel32 {

GUEST_PTR WINAPI GetCommandLineA() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCommandLineA() -> %s\n", wibo::commandLine.c_str());
	if (g_commandLineA == GUEST_NULL) {
		void *tmp = wibo::heap::guestMalloc(wibo::commandLine.size() + 1, true);
		memcpy(tmp, wibo::commandLine.c_str(), wibo::commandLine.size());
		g_commandLineA = toGuestPtr(tmp);
	}
	return g_commandLineA;
}

GUEST_PTR WINAPI GetCommandLineW() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCommandLineW() -> %s\n", wideStringToString(wibo::commandLineW.data()).c_str());
	if (g_commandLineW == GUEST_NULL) {
		void *tmp = wibo::heap::guestMalloc(wibo::commandLineW.size() * sizeof(WCHAR) + sizeof(WCHAR), true);
		memcpy(tmp, wibo::commandLineW.data(), wibo::commandLineW.size() * sizeof(WCHAR));
		g_commandLineW = toGuestPtr(tmp);
	}
	return g_commandLineW;
}

HANDLE WINAPI GetStdHandle(DWORD nStdHandle) {
	HOST_CONTEXT_GUARD();
	HANDLE handle = files::getStdHandle(nStdHandle);
	DEBUG_LOG("GetStdHandle(%d) -> %p\n", nStdHandle, handle);
	return handle;
}

BOOL WINAPI SetStdHandle(DWORD nStdHandle, HANDLE hHandle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetStdHandle(%d, %p)\n", nStdHandle, hHandle);
	return files::setStdHandle(nStdHandle, hHandle);
}

GUEST_PTR WINAPI GetEnvironmentStrings() { return GetEnvironmentStringsA(); }

GUEST_PTR WINAPI GetEnvironmentStringsA() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetEnvironmentStrings()\n");

	size_t bufSize = 0;
	char **work = environ;

	while (*work) {
		bufSize += strlen(*work) + 1;
		work++;
	}
	bufSize++;

	char *buffer = static_cast<char *>(wibo::heap::guestMalloc(bufSize));
	if (!buffer) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	char *ptr = buffer;
	work = environ;

	while (*work) {
		size_t strSize = strlen(*work);
		memcpy(ptr, *work, strSize);
		ptr[strSize] = 0;
		ptr += strSize + 1;
		work++;
	}
	*ptr = 0;

	return toGuestPtr(buffer);
}

GUEST_PTR WINAPI GetEnvironmentStringsW() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetEnvironmentStringsW()\n");

	size_t bufSizeW = 0;
	char **work = environ;

	while (*work) {
		bufSizeW += strlen(*work) + 1;
		work++;
	}
	bufSizeW++;

	uint16_t *buffer = static_cast<uint16_t *>(wibo::heap::guestMalloc(bufSizeW * sizeof(uint16_t)));
	if (!buffer) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	uint16_t *ptr = buffer;
	work = environ;

	while (*work) {
		VERBOSE_LOG("-> %s\n", *work);
		size_t strSize = strlen(*work);
		for (size_t i = 0; i < strSize; i++) {
			*ptr++ = static_cast<uint8_t>((*work)[i]);
		}
		*ptr++ = 0;
		work++;
	}
	*ptr = 0;

	return toGuestPtr(buffer);
}

BOOL WINAPI FreeEnvironmentStringsA(LPCH penv) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FreeEnvironmentStringsA(%p)\n", penv);
	if (!penv) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	wibo::heap::guestFree(penv);
	return TRUE;
}

BOOL WINAPI FreeEnvironmentStringsW(LPWCH penv) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FreeEnvironmentStringsW(%p)\n", penv);
	if (!penv) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	wibo::heap::guestFree(penv);
	return TRUE;
}

DWORD WINAPI GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetEnvironmentVariableA(%s, %p, %u)\n", lpName ? lpName : "(null)", lpBuffer, nSize);
	if (!lpName) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	const char *rawValue = getenv(lpName);
	if (!rawValue) {
		setLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	std::string converted = convertEnvValueForWindows(lpName, rawValue);
	const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
	DWORD len = static_cast<DWORD>(finalValue.size());
	if (nSize == 0) {
		return len + 1;
	}
	if (!lpBuffer) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (nSize <= len) {
		return len + 1;
	}
	memcpy(lpBuffer, finalValue.c_str(), len + 1);
	return len;
}

DWORD WINAPI GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	std::string name = lpName ? wideStringToString(lpName) : std::string();
	DEBUG_LOG("GetEnvironmentVariableW(%s, %p, %u)\n", name.c_str(), lpBuffer, nSize);
	if (name.empty()) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	const char *rawValue = getenv(name.c_str());
	if (!rawValue) {
		setLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	std::string converted = convertEnvValueForWindows(name, rawValue);
	const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
	auto wideValue = stringToWideString(finalValue.c_str());
	DWORD required = static_cast<DWORD>(wideValue.size());
	if (nSize == 0) {
		return required;
	}
	if (!lpBuffer) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (nSize < required) {
		return required;
	}
	std::copy(wideValue.begin(), wideValue.end(), lpBuffer);
	return required - 1;
}

BOOL WINAPI SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetEnvironmentVariableA(%s, %s)\n", lpName ? lpName : "(null)", lpValue ? lpValue : "(null)");
	if (!lpName || std::strchr(lpName, '=')) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	int rc = 0;
	if (!lpValue) {
		rc = unsetenv(lpName);
		if (rc != 0) {
			setLastErrorFromErrno();
			return FALSE;
		}
		return TRUE;
	}
	std::string hostValue = convertEnvValueToHost(lpName, lpValue);
	const char *valuePtr = hostValue.empty() ? lpValue : hostValue.c_str();
	rc = setenv(lpName, valuePtr, 1);
	if (rc != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetEnvironmentVariableW -> ");
	if (!lpName) {
		setLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string name = wideStringToString(lpName);
	std::string value = lpValue ? wideStringToString(lpValue) : std::string();
	return SetEnvironmentVariableA(name.c_str(), lpValue ? value.c_str() : nullptr);
}

} // namespace kernel32
