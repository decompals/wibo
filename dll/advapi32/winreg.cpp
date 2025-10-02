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

struct RegistryKeyHandleData {
	std::u16string canonicalPath;
	bool predefined = false;
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

std::mutex registryMutex;
bool predefinedHandlesInitialized = false;
RegistryKeyHandleData predefinedHandles[kPredefinedKeyCount];
bool registryInitialized = false;
std::unordered_set<std::u16string> existingKeys;

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

void initializePredefinedHandlesLocked() {
	if (predefinedHandlesInitialized) {
		return;
	}
	for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
		predefinedHandles[i].canonicalPath = canonicalizeKeySegment(std::u16string(kPredefinedKeyInfos[i].name));
		predefinedHandles[i].predefined = true;
	}
	predefinedHandlesInitialized = true;
}

RegistryKeyHandleData *predefinedHandleForValue(uintptr_t value) {
	for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
		if (kPredefinedKeyInfos[i].value == value) {
			return &predefinedHandles[i];
		}
	}
	return nullptr;
}

RegistryKeyHandleData *handleDataFromHKeyLocked(HKEY hKey) {
	uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
	if (raw == 0) {
		return nullptr;
	}
	initializePredefinedHandlesLocked();
	if (auto *predefined = predefinedHandleForValue(raw)) {
		return predefined;
	}
	auto data = handles::dataFromHandle(hKey, false);
	if (data.type != handles::TYPE_REGISTRY_KEY || data.ptr == nullptr) {
		return nullptr;
	}
	return static_cast<RegistryKeyHandleData *>(data.ptr);
}

bool isPredefinedKeyHandle(HKEY hKey) {
	uintptr_t raw = reinterpret_cast<uintptr_t>(hKey);
	for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
		if (kPredefinedKeyInfos[i].value == raw) {
			return true;
		}
	}
	return false;
}

void ensureRegistryInitializedLocked() {
	if (registryInitialized) {
		return;
	}
	initializePredefinedHandlesLocked();
	for (size_t i = 0; i < kPredefinedKeyCount; ++i) {
		existingKeys.insert(predefinedHandles[i].canonicalPath);
	}
	registryInitialized = true;
}

} // namespace

namespace advapi32 {

LSTATUS WIN_FUNC RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
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
	std::lock_guard<std::mutex> lock(registryMutex);
	ensureRegistryInitializedLocked();
	RegistryKeyHandleData *baseHandle = handleDataFromHKeyLocked(hKey);
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
	if (existingKeys.find(targetPath) == existingKeys.end()) {
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
	auto *handleData = new RegistryKeyHandleData;
	handleData->canonicalPath = targetPath;
	handleData->predefined = false;
	auto handle = handles::allocDataHandle({handles::TYPE_REGISTRY_KEY, handleData, sizeof(*handleData)});
	*phkResult = reinterpret_cast<HKEY>(handle);
	wibo::lastError = ERROR_SUCCESS;
	return ERROR_SUCCESS;
}

LSTATUS WIN_FUNC RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
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

LSTATUS WIN_FUNC RegCloseKey(HKEY hKey) {
	DEBUG_LOG("RegCloseKey(%p)\n", hKey);
	if (isPredefinedKeyHandle(hKey)) {
		wibo::lastError = ERROR_SUCCESS;
		return ERROR_SUCCESS;
	}
	auto data = handles::dataFromHandle(hKey, true);
	if (data.type != handles::TYPE_REGISTRY_KEY || data.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return ERROR_INVALID_HANDLE;
	}
	auto *handleData = static_cast<RegistryKeyHandleData *>(data.ptr);
	delete handleData;
	wibo::lastError = ERROR_SUCCESS;
	return ERROR_SUCCESS;
}

} // namespace advapi32
