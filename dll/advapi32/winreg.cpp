#include "winreg.h"

#include "errors.h"
#include "handles.h"
#include "strutil.h"

#include <iterator>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

struct RegistryKeyObject : ObjectBase {
	static constexpr ObjectType kType = ObjectType::RegistryKey;

	std::mutex m;
	std::u16string canonicalPath;
	bool closed = false;
	bool predefined = false;

	RegistryKeyObject() : ObjectBase(kType) {}
	explicit RegistryKeyObject(std::u16string path) : ObjectBase(kType), canonicalPath(std::move(path)) {}
};

struct PredefinedKeyInfo {
	uintptr_t value;
	const char16_t *name;
};

constexpr PredefinedKeyInfo kPredefinedKeyInfos[] = {
	{static_cast<uintptr_t>(0x80000000u), u"HKEY_CLASSES_ROOT"},
	{static_cast<uintptr_t>(0x80000001u), u"HKEY_CURRENT_USER"},
	{static_cast<uintptr_t>(0x80000002u), u"HKEY_LOCAL_MACHINE"},
	{static_cast<uintptr_t>(0x80000003u), u"HKEY_USERS"},
	{static_cast<uintptr_t>(0x80000004u), u"HKEY_PERFORMANCE_DATA"},
	{static_cast<uintptr_t>(0x80000005u), u"HKEY_CURRENT_CONFIG"},
};

constexpr size_t kPredefinedKeyCount = std::size(kPredefinedKeyInfos);

std::mutex g_registryMutex;
std::unordered_set<std::u16string> g_existingKeys;

std::u16string canonicalizeKeySegment(const std::u16string &input) {
	std::u16string result;
	result.reserve(input.size());
	bool lastWasSlash = false;
	for (char16_t ch : input) {
		char16_t normalized = (ch == u'/') ? u'\\' : ch;
		if (normalized == u'\\') {
			if (!result.empty() && !lastWasSlash) {
				result.push_back(u'\\');
			}
			lastWasSlash = true;
			continue;
		}
		lastWasSlash = false;
		uint16_t lowered = wcharToLower(static_cast<uint16_t>(normalized));
		result.push_back(static_cast<char16_t>(lowered));
	}
	while (!result.empty() && result.back() == u'\\') {
		result.pop_back();
	}
	auto it = result.begin();
	while (it != result.end() && *it == u'\\') {
		it = result.erase(it);
	}
	return result;
}

std::u16string canonicalizeKeySegment(LPCWSTR input) {
	if (!input) {
		return {};
	}
	std::u16string wide(reinterpret_cast<const char16_t *>(input), wstrlen(input));
	return canonicalizeKeySegment(wide);
}

Pin<RegistryKeyObject> predefinedHandleForValue(uintptr_t value) {
	static std::array<Pin<RegistryKeyObject>, kPredefinedKeyCount> g_predefinedHandles = [] {
		std::array<Pin<RegistryKeyObject>, kPredefinedKeyCount> arr;
		for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
			arr[i] = make_pin<RegistryKeyObject>();
			arr[i]->canonicalPath = canonicalizeKeySegment(std::u16string(kPredefinedKeyInfos[i].name));
			arr[i]->predefined = true;
		}
		return arr;
	}();
	for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
		if (kPredefinedKeyInfos[i].value == value) {
			return g_predefinedHandles[i].clone();
		}
	}
	return {};
}

Pin<RegistryKeyObject> handleDataFromHKeyLocked(HKEY hKey) {
	uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
	if (raw == 0) {
		return {};
	}
	if (auto predefined = predefinedHandleForValue(raw)) {
		return predefined;
	}
	auto obj = wibo::handles().getAs<RegistryKeyObject>(hKey);
	if (!obj || obj->closed) {
		return {};
	}
	return obj;
}

bool isPredefinedKeyHandle(HKEY hKey) {
	uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
	for (const auto &kPredefinedKeyInfo : kPredefinedKeyInfos) {
		if (kPredefinedKeyInfo.value == raw) {
			return true;
		}
	}
	return false;
}

} // namespace

namespace advapi32 {

LSTATUS WIN_FUNC RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions,
								 REGSAM samDesired, void *lpSecurityAttributes, PHKEY phkResult,
								 LPDWORD lpdwDisposition) {
	HOST_CONTEXT_GUARD();
	std::string subKeyString = lpSubKey ? wideStringToString(lpSubKey) : std::string("(null)");
	std::string classString = lpClass ? wideStringToString(lpClass) : std::string("(null)");
	DEBUG_LOG("RegCreateKeyExW(%p, %s, %u, %s, 0x%x, 0x%x, %p, %p, %p)\n", hKey, subKeyString.c_str(), Reserved,
			  classString.c_str(), dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	(void)lpClass;
	(void)lpSecurityAttributes;
	if (!phkResult) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	*phkResult = nullptr;
	if (Reserved != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	if (dwOptions != 0) {
		DEBUG_LOG("RegCreateKeyExW: unsupported options 0x%x\n", dwOptions);
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	REGSAM sanitizedAccess = samDesired & ~(KEY_WOW64_64KEY | KEY_WOW64_32KEY);
	if (sanitizedAccess != samDesired) {
		DEBUG_LOG("RegCreateKeyExW: ignoring WOW64 access mask 0x%x\n", samDesired ^ sanitizedAccess);
	}
	std::lock_guard<std::mutex> lock(g_registryMutex);
	Pin<RegistryKeyObject> baseHandle = handleDataFromHKeyLocked(hKey);
	if (!baseHandle) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	std::u16string targetPath = baseHandle->canonicalPath;
	bool targetingBase = true;
	if (lpSubKey && lpSubKey[0] != 0) {
		std::u16string subComponent = canonicalizeKeySegment(lpSubKey);
		if (!subComponent.empty()) {
			targetingBase = false;
			if (!targetPath.empty()) {
				targetPath.push_back(u'\\');
			}
			targetPath.append(subComponent);
		}
	}
	if (targetPath.empty()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	bool existed = g_existingKeys.find(targetPath) != g_existingKeys.end();
	if (!existed) {
		g_existingKeys.insert(targetPath);
	}
	if (lpdwDisposition) {
		*lpdwDisposition = existed ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
	}
	if (targetingBase) {
		*phkResult = hKey;
		wibo::lastError = ERROR_SUCCESS;
		return ERROR_SUCCESS;
	}
	auto obj = make_pin<RegistryKeyObject>(std::move(targetPath));
	auto handle = wibo::handles().alloc(std::move(obj), 0, 0);
	*phkResult = reinterpret_cast<HKEY>(handle);
	wibo::lastError = ERROR_SUCCESS;
	return ERROR_SUCCESS;
}

LSTATUS WIN_FUNC RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions,
								 REGSAM samDesired, void *lpSecurityAttributes, PHKEY phkResult,
								 LPDWORD lpdwDisposition) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegCreateKeyExA(%p, %s, %u, %s, 0x%x, 0x%x, %p, %p, %p)\n", hKey, lpSubKey ? lpSubKey : "(null)",
			  Reserved, lpClass ? lpClass : "(null)", dwOptions, samDesired, lpSecurityAttributes, phkResult,
			  lpdwDisposition);
	std::vector<uint16_t> subKeyWideStorage;
	if (lpSubKey) {
		subKeyWideStorage = stringToWideString(lpSubKey);
	}
	std::vector<uint16_t> classWideStorage;
	if (lpClass) {
		classWideStorage = stringToWideString(lpClass);
	}
	return RegCreateKeyExW(hKey, lpSubKey ? reinterpret_cast<LPCWSTR>(subKeyWideStorage.data()) : nullptr, Reserved,
						   lpClass ? reinterpret_cast<LPWSTR>(classWideStorage.data()) : nullptr, dwOptions, samDesired,
						   lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS WIN_FUNC RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
	HOST_CONTEXT_GUARD();
	std::string subKeyString = lpSubKey ? wideStringToString(lpSubKey) : std::string("(null)");
	DEBUG_LOG("RegOpenKeyExW(%p, %s, %u, 0x%x, %p)\n", hKey, subKeyString.c_str(), ulOptions, samDesired, phkResult);
	if (!phkResult) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	*phkResult = nullptr;
	if ((ulOptions & ~REG_OPTION_OPEN_LINK) != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	if (ulOptions & REG_OPTION_OPEN_LINK) {
		DEBUG_LOG("RegOpenKeyExW: ignoring REG_OPTION_OPEN_LINK\n");
	}
	REGSAM sanitizedAccess = samDesired & ~(KEY_WOW64_64KEY | KEY_WOW64_32KEY);
	if (sanitizedAccess != samDesired) {
		DEBUG_LOG("RegOpenKeyExW: ignoring WOW64 access mask 0x%x\n", samDesired ^ sanitizedAccess);
	}
	(void)sanitizedAccess;
	std::lock_guard<std::mutex> lock(g_registryMutex);
	Pin<RegistryKeyObject> baseHandle = handleDataFromHKeyLocked(hKey);
	if (!baseHandle) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	std::u16string targetPath = baseHandle->canonicalPath;
	if (lpSubKey && lpSubKey[0] != 0) {
		std::u16string subComponent = canonicalizeKeySegment(lpSubKey);
		if (!subComponent.empty()) {
			if (!targetPath.empty()) {
				targetPath.push_back(u'\\');
			}
			targetPath.append(subComponent);
		}
	}
	if (targetPath.empty()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	if (g_existingKeys.find(targetPath) == g_existingKeys.end()) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return ERROR_FILE_NOT_FOUND;
	}
	if (!lpSubKey || lpSubKey[0] == 0) {
		if (baseHandle->predefined) {
			*phkResult = hKey;
			wibo::lastError = ERROR_SUCCESS;
			return ERROR_SUCCESS;
		}
	}
	auto obj = make_pin<RegistryKeyObject>(std::move(targetPath));
	auto handle = wibo::handles().alloc(std::move(obj), 0, 0);
	*phkResult = reinterpret_cast<HKEY>(handle);
	wibo::lastError = ERROR_SUCCESS;
	return ERROR_SUCCESS;
}

LSTATUS WIN_FUNC RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegOpenKeyExA(%p, %s, %u, 0x%x, %p)\n", hKey, lpSubKey ? lpSubKey : "(null)", ulOptions, samDesired,
			  phkResult);
	LPCWSTR widePtr = nullptr;
	std::vector<uint16_t> wideStorage;
	if (lpSubKey) {
		wideStorage = stringToWideString(lpSubKey);
		widePtr = reinterpret_cast<LPCWSTR>(wideStorage.data());
	}
	return RegOpenKeyExW(hKey, widePtr, ulOptions, samDesired, phkResult);
}

LSTATUS WIN_FUNC RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
								  LPDWORD lpcbData) {
	HOST_CONTEXT_GUARD();
	std::string valueName = lpValueName ? wideStringToString(lpValueName) : std::string("(default)");
	DEBUG_LOG("RegQueryValueExW(%p, %s, %p, %p, %p, %p)\n", hKey, valueName.c_str(), lpReserved, lpType, lpData,
			  lpcbData);
	if (lpReserved) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	if (lpcbData) {
		*lpcbData = 0;
	}
	if (lpType) {
		*lpType = 0;
	}
	(void)hKey;
	(void)lpData;
	wibo::lastError = ERROR_FILE_NOT_FOUND;
	return ERROR_FILE_NOT_FOUND;
}

LSTATUS WIN_FUNC RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
								  LPDWORD lpcbData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegQueryValueExA(%p, %s, %p, %p, %p, %p)\n", hKey, lpValueName ? lpValueName : "(null)", lpReserved,
			  lpType, lpData, lpcbData);
	std::vector<uint16_t> valueWideStorage;
	if (lpValueName) {
		valueWideStorage = stringToWideString(lpValueName);
	}
	return RegQueryValueExW(hKey, lpValueName ? reinterpret_cast<LPCWSTR>(valueWideStorage.data()) : nullptr,
							lpReserved, lpType, lpData, lpcbData);
}

LSTATUS WIN_FUNC RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
							   LPWSTR lpClass, LPDWORD lpcchClass, FILETIME *lpftLastWriteTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegEnumKeyExW(%p, %u, %p, %p, %p, %p, %p, %p)\n", hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass,
			  lpcchClass, lpftLastWriteTime);
	(void)hKey;
	(void)dwIndex;
	if (lpReserved) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	if (lpcchName) {
		*lpcchName = 0;
	}
	if (lpName && lpcchName && *lpcchName > 0) {
		lpName[0] = 0;
	}
	if (lpClass && lpcchClass && *lpcchClass > 0) {
		lpClass[0] = 0;
	}
	if (lpcchClass) {
		*lpcchClass = 0;
	}
	(void)lpftLastWriteTime;
	wibo::lastError = ERROR_NO_MORE_ITEMS;
	return ERROR_NO_MORE_ITEMS;
}

LSTATUS WIN_FUNC RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
							   LPSTR lpClass, LPDWORD lpcchClass, FILETIME *lpftLastWriteTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegEnumKeyExA(%p, %u, %p, %p, %p, %p, %p, %p)\n", hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass,
			  lpcchClass, lpftLastWriteTime);
	(void)hKey;
	(void)dwIndex;
	if (lpReserved) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return ERROR_INVALID_PARAMETER;
	}
	if (lpcchName) {
		*lpcchName = 0;
	}
	if (lpName && lpcchName && *lpcchName > 0) {
		lpName[0] = '\0';
	}
	if (lpClass && lpcchClass && *lpcchClass > 0) {
		lpClass[0] = '\0';
	}
	if (lpcchClass) {
		*lpcchClass = 0;
	}
	(void)lpftLastWriteTime;
	wibo::lastError = ERROR_NO_MORE_ITEMS;
	return ERROR_NO_MORE_ITEMS;
}

LSTATUS WIN_FUNC RegCloseKey(HKEY hKey) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RegCloseKey(%p)\n", hKey);
	if (isPredefinedKeyHandle(hKey)) {
		wibo::lastError = ERROR_SUCCESS;
		return ERROR_SUCCESS;
	}
	auto obj = wibo::handles().getAs<RegistryKeyObject>(hKey);
	if (!obj || obj->closed) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return ERROR_SUCCESS;
}

} // namespace advapi32
