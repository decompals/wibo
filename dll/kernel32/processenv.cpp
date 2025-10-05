#include "processenv.h"

#include "errors.h"
#include "files.h"
#include "internal.h"
#include "strutil.h"

#include <cstdlib>
#include <cstring>
#include <mimalloc.h>
#include <string>
#include <strings.h>
#include <unistd.h>

namespace {

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

LPSTR WIN_FUNC GetCommandLineA() {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetCommandLineA() -> %s\n", wibo::commandLine.c_str());
	wibo::lastError = ERROR_SUCCESS;
	return const_cast<LPSTR>(wibo::commandLine.c_str());
}

LPWSTR WIN_FUNC GetCommandLineW() {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetCommandLineW() -> %s\n", wideStringToString(wibo::commandLineW.data()).c_str());
	wibo::lastError = ERROR_SUCCESS;
	return wibo::commandLineW.data();
}

HANDLE WIN_FUNC GetStdHandle(DWORD nStdHandle) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetStdHandle(%d)\n", nStdHandle);
	return files::getStdHandle(nStdHandle);
}

BOOL WIN_FUNC SetStdHandle(DWORD nStdHandle, HANDLE hHandle) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetStdHandle(%d, %p)\n", nStdHandle, hHandle);
	return files::setStdHandle(nStdHandle, hHandle);
}

LPCH WIN_FUNC GetEnvironmentStrings() {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetEnvironmentStrings()\n");

	size_t bufSize = 0;
	char **work = environ;

	while (*work) {
		bufSize += strlen(*work) + 1;
		work++;
	}
	bufSize++;

	char *buffer = static_cast<char *>(mi_malloc(bufSize));
	if (!buffer) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
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

	wibo::lastError = ERROR_SUCCESS;
	return buffer;
}

LPWCH WIN_FUNC GetEnvironmentStringsW() {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetEnvironmentStringsW()\n");

	size_t bufSizeW = 0;
	char **work = environ;

	while (*work) {
		bufSizeW += strlen(*work) + 1;
		work++;
	}
	bufSizeW++;

	uint16_t *buffer = static_cast<uint16_t *>(mi_malloc(bufSizeW * sizeof(uint16_t)));
	if (!buffer) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
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

	wibo::lastError = ERROR_SUCCESS;
	return buffer;
}

BOOL WIN_FUNC FreeEnvironmentStringsA(LPCH penv) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("FreeEnvironmentStringsA(%p)\n", penv);
	if (!penv) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	free(penv);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC FreeEnvironmentStringsW(LPWCH penv) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("FreeEnvironmentStringsW(%p)\n", penv);
	if (!penv) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	free(penv);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetEnvironmentVariableA(%s, %p, %u)\n", lpName ? lpName : "(null)", lpBuffer, nSize);
	if (!lpName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	const char *rawValue = getenv(lpName);
	if (!rawValue) {
		wibo::lastError = ERROR_ENVVAR_NOT_FOUND;
		return 0;
	}
	std::string converted = convertEnvValueForWindows(lpName, rawValue);
	const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
	DWORD len = static_cast<DWORD>(finalValue.size());
	if (nSize == 0) {
		wibo::lastError = ERROR_SUCCESS;
		return len + 1;
	}
	if (!lpBuffer) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (nSize <= len) {
		wibo::lastError = ERROR_SUCCESS;
		return len + 1;
	}
	memcpy(lpBuffer, finalValue.c_str(), len + 1);
	wibo::lastError = ERROR_SUCCESS;
	return len;
}

DWORD WIN_FUNC GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
	WIN_API_SEGMENT_GUARD();
	std::string name = lpName ? wideStringToString(lpName) : std::string();
	DEBUG_LOG("GetEnvironmentVariableW(%s, %p, %u)\n", name.c_str(), lpBuffer, nSize);
	if (name.empty()) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	const char *rawValue = getenv(name.c_str());
	if (!rawValue) {
		wibo::lastError = ERROR_ENVVAR_NOT_FOUND;
		return 0;
	}
	std::string converted = convertEnvValueForWindows(name, rawValue);
	const std::string &finalValue = converted.empty() ? std::string(rawValue) : converted;
	auto wideValue = stringToWideString(finalValue.c_str());
	DWORD required = static_cast<DWORD>(wideValue.size());
	if (nSize == 0) {
		wibo::lastError = ERROR_SUCCESS;
		return required;
	}
	if (!lpBuffer) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (nSize < required) {
		wibo::lastError = ERROR_SUCCESS;
		return required;
	}
	std::copy(wideValue.begin(), wideValue.end(), lpBuffer);
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

BOOL WIN_FUNC SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetEnvironmentVariableA(%s, %s)\n", lpName ? lpName : "(null)", lpValue ? lpValue : "(null)");
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
	rc = setenv(lpName, valuePtr, 1);
	if (rc != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetEnvironmentVariableW -> ");
	if (!lpName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string name = wideStringToString(lpName);
	std::string value = lpValue ? wideStringToString(lpValue) : std::string();
	return SetEnvironmentVariableA(name.c_str(), lpValue ? value.c_str() : nullptr);
}

} // namespace kernel32
