#include "processenv.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "heap.h"
#include "internal.h"
#include "strutil.h"
#include "types.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mimalloc.h>
#include <optional>
#include <string>
#include <string_view>
#include <strings.h>
#include <unistd.h>
#include <vector>

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
		if (strcasecmp(name.c_str(), "TMP") != 0 && strcasecmp(name.c_str(), "TEMP") != 0) {
			return rawValue;
		}
		std::string path = rawValue;
		bool looksWindows =
			path.find('\\') != std::string::npos || (path.size() >= 2 && path[1] == ':' && path[0] != '/');
		if (looksWindows) {
			std::replace(path.begin(), path.end(), '/', '\\');
			return path;
		}
		return files::pathToWindows(std::filesystem::path(path));
	}
	std::string converted = files::hostPathListToWindows(rawValue);
	return converted.empty() ? std::string(rawValue) : converted;
}

const char *getenvCaseInsensitive(const std::string &name) {
	if (const char *exact = getenv(name.c_str())) {
		return exact;
	}
	for (char **work = environ; *work; ++work) {
		std::string_view entry(*work);
		size_t eq = entry.find('=');
		if (eq != std::string_view::npos && entry.size() >= eq + 1 && entry.compare(0, eq, name) == 0) {
			return entry.data() + eq + 1;
		}
		if (eq != std::string_view::npos && entry.size() >= eq + 1) {
			std::string envName(entry.substr(0, eq));
			if (strcasecmp(envName.c_str(), name.c_str()) == 0) {
				return entry.data() + eq + 1;
			}
		}
	}
	return nullptr;
}

std::optional<std::string> synthesizedTempEnvValue(const std::string &name) {
	if (strcasecmp(name.c_str(), "TMP") != 0 && strcasecmp(name.c_str(), "TEMP") != 0) {
		return std::nullopt;
	}

	const char *hostTemp = getenv("TMPDIR");
	if (!hostTemp || !*hostTemp) {
		hostTemp = "/tmp";
	}
	return convertEnvValueForWindows(name, hostTemp);
}

std::optional<std::string> getEnvValueForWindows(const std::string &name) {
	if (const char *rawValue = getenvCaseInsensitive(name)) {
		return convertEnvValueForWindows(name, rawValue);
	}
	return synthesizedTempEnvValue(name);
}

std::vector<std::string> prepareEnvStrings(size_t &totalSize) {
	std::vector<std::string> strings;
	totalSize = 0;
	bool hasTmp = false;
	bool hasTemp = false;
	for (char **work = environ; *work; ++work) {
		std::string s = *work;
		size_t eq = s.find('=');
		if (eq != std::string::npos) {
			std::string name = s.substr(0, eq);
			std::string value = s.substr(eq + 1);
			std::string converted = convertEnvValueForWindows(name, value.c_str());
			s = name + "=" + converted;
			if (strcasecmp(name.c_str(), "TMP") == 0) {
				hasTmp = true;
			} else if (strcasecmp(name.c_str(), "TEMP") == 0) {
				hasTemp = true;
			}
		}
		strings.push_back(s);
		totalSize += s.size() + 1;
	}

	const auto addSynthesizedEnv = [&](const char *name, bool present) {
		if (present) {
			return;
		}
		auto value = synthesizedTempEnvValue(name);
		if (!value) {
			return;
		}
		std::string s = std::string(name) + "=" + *value;
		totalSize += s.size() + 1;
		strings.push_back(std::move(s));
	};
	addSynthesizedEnv("TMP", hasTmp);
	addSynthesizedEnv("TEMP", hasTemp);

	totalSize++; // For the final null
	return strings;
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
	DEBUG_LOG("GetEnvironmentStringsA()\n");

	size_t bufSize = 0;
	auto strings = prepareEnvStrings(bufSize);

	char *buffer = static_cast<char *>(wibo::heap::guestMalloc(bufSize));
	if (!buffer) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	char *ptr = buffer;
	for (const auto &s : strings) {
		memcpy(ptr, s.c_str(), s.size());
		ptr[s.size()] = 0;
		ptr += s.size() + 1;
	}
	*ptr = 0;

	return toGuestPtr(buffer);
}

GUEST_PTR WINAPI GetEnvironmentStringsW() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetEnvironmentStringsW()\n");

	size_t bufSizeW = 0;
	auto strings = prepareEnvStrings(bufSizeW);

	uint16_t *buffer = static_cast<uint16_t *>(wibo::heap::guestMalloc(bufSizeW * sizeof(uint16_t)));
	if (!buffer) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	uint16_t *ptr = buffer;
	for (const auto &s : strings) {
		for (char c : s) {
			*ptr++ = static_cast<uint16_t>(static_cast<unsigned char>(c));
		}
		*ptr++ = 0;
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
	auto value = getEnvValueForWindows(lpName);
	if (!value) {
		setLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	DWORD len = static_cast<DWORD>(value->size());
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
	memcpy(lpBuffer, value->c_str(), len + 1);
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
	auto value = getEnvValueForWindows(name);
	if (!value) {
		setLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	auto wideValue = stringToWideString(value->c_str());
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
