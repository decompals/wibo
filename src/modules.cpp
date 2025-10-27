#include "modules.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "strutil.h"
#include "tls.h"

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern const wibo::ModuleStub lib_advapi32;
extern const wibo::ModuleStub lib_bcrypt;
extern const wibo::ModuleStub lib_crt;
extern const wibo::ModuleStub lib_kernel32;
extern const wibo::ModuleStub lib_lmgr;
extern const wibo::ModuleStub lib_mscoree;
extern const wibo::ModuleStub lib_msvcrt;
extern const wibo::ModuleStub lib_ntdll;
extern const wibo::ModuleStub lib_rpcrt4;
extern const wibo::ModuleStub lib_ole32;
extern const wibo::ModuleStub lib_user32;
extern const wibo::ModuleStub lib_vcruntime;
extern const wibo::ModuleStub lib_version;

namespace {

constexpr DWORD DLL_PROCESS_DETACH = 0;
constexpr DWORD DLL_PROCESS_ATTACH = 1;
constexpr DWORD DLL_THREAD_ATTACH = 2;
constexpr DWORD DLL_THREAD_DETACH = 3;
constexpr DWORD TLS_PROCESS_ATTACH = DLL_PROCESS_ATTACH;
constexpr DWORD TLS_PROCESS_DETACH = DLL_PROCESS_DETACH;
constexpr DWORD TLS_THREAD_ATTACH = DLL_THREAD_ATTACH;
constexpr DWORD TLS_THREAD_DETACH = DLL_THREAD_DETACH;

struct PEExportDirectory {
	uint32_t characteristics;
	uint32_t timeDateStamp;
	uint16_t majorVersion;
	uint16_t minorVersion;
	uint32_t name;
	uint32_t base;
	uint32_t numberOfFunctions;
	uint32_t numberOfNames;
	uint32_t addressOfFunctions;
	uint32_t addressOfNames;
	uint32_t addressOfNameOrdinals;
};

using StubFuncType = void (*)();
constexpr size_t MAX_STUBS = 0x100;
size_t stubIndex = 0;
std::array<std::string, MAX_STUBS> stubDlls;
std::array<std::string, MAX_STUBS> stubFuncNames;
std::unordered_map<std::string, StubFuncType> stubCache;

std::string makeStubKey(const char *dllName, const char *funcName) {
	std::string key;
	if (dllName) {
		key.assign(dllName);
		toLowerInPlace(key);
	}
	key.push_back(':');
	if (funcName) {
		std::string func(funcName);
		toLowerInPlace(func);
		key += func;
	}
	return key;
}

void stubBase(size_t index) {
	const char *func = stubFuncNames[index].empty() ? "<unknown>" : stubFuncNames[index].c_str();
	const char *dll = stubDlls[index].empty() ? "<unknown>" : stubDlls[index].c_str();
	fprintf(stderr, "wibo: call reached missing import %s from %s\n", func, dll);
	fflush(stderr);
	abort();
}

template <size_t Index> void stubThunk() { stubBase(Index); }

template <size_t... Indices>
constexpr std::array<void (*)(void), sizeof...(Indices)> makeStubTable(std::index_sequence<Indices...>) {
	return {{stubThunk<Indices>...}};
}

constexpr auto stubFuncs = makeStubTable(std::make_index_sequence<MAX_STUBS>{});

StubFuncType resolveMissingFuncName(const char *dllName, const char *funcName) {
	DEBUG_LOG("Missing function: %s (%s)\n", dllName, funcName);
	std::string key = makeStubKey(dllName, funcName);
	auto existing = stubCache.find(key);
	if (existing != stubCache.end()) {
		return existing->second;
	}
	if (stubIndex >= MAX_STUBS) {
		fprintf(stderr, "wibo: too many missing functions encountered (>%zu). Last failure: %s (%s)\n", MAX_STUBS,
				funcName, dllName);
		fflush(stderr);
		abort();
	}
	stubFuncNames[stubIndex] = funcName ? funcName : "";
	stubDlls[stubIndex] = dllName ? dllName : "";
	StubFuncType stub = stubFuncs[stubIndex];
	stubCache.emplace(std::move(key), stub);
	stubIndex++;
	return stub;
}

StubFuncType resolveMissingFuncOrdinal(const char *dllName, uint16_t ordinal) {
	char buf[16];
	sprintf(buf, "%d", ordinal);
	return resolveMissingFuncName(dllName, buf);
}

struct ModuleRegistry {
	std::recursive_mutex mutex;
	std::unordered_map<std::string, wibo::ModulePtr> modulesByKey;
	std::unordered_map<std::string, wibo::ModuleInfo *> modulesByAlias;
	std::optional<std::filesystem::path> dllDirectory;
	bool initialized = false;
	std::unordered_map<void *, wibo::ModuleInfo *> onExitTables;
	std::unordered_map<const wibo::ModuleStub *, std::vector<std::string>> builtinAliasLists;
	std::unordered_map<std::string, wibo::ModuleInfo *> builtinAliasMap;
	std::unordered_set<std::string> pinnedAliases;
	std::unordered_set<wibo::ModuleInfo *> pinnedModules;
};

struct LockedRegistry {
	ModuleRegistry *reg;
	std::unique_lock<std::recursive_mutex> lock;

	LockedRegistry(ModuleRegistry &registryRef, std::unique_lock<std::recursive_mutex> &&guard)
		: reg(&registryRef), lock(std::move(guard)) {}

	LockedRegistry(const LockedRegistry &) = delete;
	LockedRegistry &operator=(const LockedRegistry &) = delete;
	LockedRegistry(LockedRegistry &&) = default;
	LockedRegistry &operator=(LockedRegistry &&) = default;

	[[nodiscard]] ModuleRegistry &get() const { return *reg; }
	ModuleRegistry *operator->() const { return reg; }
	ModuleRegistry &operator*() const { return *reg; }
};

void registerBuiltinModule(ModuleRegistry &reg, const wibo::ModuleStub *module);

LockedRegistry registry() {
	static ModuleRegistry reg;
	std::unique_lock guard(reg.mutex);
	if (!reg.initialized) {
		reg.initialized = true;
		const wibo::ModuleStub *builtins[] = {
			&lib_advapi32, &lib_bcrypt, &lib_crt,	 &lib_kernel32, &lib_lmgr,		&lib_mscoree, &lib_msvcrt,
			&lib_ntdll,	   &lib_ole32,	&lib_rpcrt4, &lib_user32,	&lib_vcruntime, &lib_version, nullptr,
		};
		for (const wibo::ModuleStub **module = builtins; *module; ++module) {
			registerBuiltinModule(reg, *module);
		}
	}
	return {reg, std::move(guard)};
}

std::string normalizeAlias(const std::string &value) {
	std::string out = value;
	std::replace(out.begin(), out.end(), '/', '\\');
	toLowerInPlace(out);
	return out;
}

struct ParsedModuleName {
	std::string original;
	std::string directory; // Windows-style directory component (may be empty)
	std::string base;
	bool hasExtension = false;
	bool endsWithDot = false;
};

ParsedModuleName parseModuleName(const std::string &name) {
	ParsedModuleName parsed;
	parsed.original = name;
	parsed.base = name;
	std::string sanitized = name;
	std::replace(sanitized.begin(), sanitized.end(), '/', '\\');
	auto sep = sanitized.find_last_of('\\');
	if (sep != std::string::npos) {
		parsed.directory = sanitized.substr(0, sep);
		parsed.base = sanitized.substr(sep + 1);
	} else {
		parsed.base = sanitized;
	}
	parsed.endsWithDot = !parsed.base.empty() && parsed.base.back() == '.';
	parsed.hasExtension = (!parsed.endsWithDot) && parsed.base.find('.') != std::string::npos;
	return parsed;
}

std::vector<std::string> candidateModuleNames(const ParsedModuleName &parsed) {
	std::vector<std::string> names;
	if (!parsed.base.empty()) {
		names.push_back(parsed.base);
		if (!parsed.hasExtension && !parsed.endsWithDot) {
			names.push_back(parsed.base + ".dll");
		}
	}
	return names;
}

std::string normalizedBaseKey(const ParsedModuleName &parsed) {
	if (parsed.base.empty()) {
		return {};
	}
	std::string base = parsed.base;
	if (!parsed.hasExtension && !parsed.endsWithDot) {
		base += ".dll";
	}
	return normalizeAlias(base);
}

struct ImageTlsDirectory32 {
	uint32_t StartAddressOfRawData;
	uint32_t EndAddressOfRawData;
	uint32_t AddressOfIndex;
	uint32_t AddressOfCallBacks;
	uint32_t SizeOfZeroFill;
	uint32_t Characteristics;
};

uintptr_t resolveModuleAddress(const wibo::Executable &exec, uintptr_t address) {
	if (address == 0) {
		return 0;
	}
	const uintptr_t actualBase = reinterpret_cast<uintptr_t>(exec.imageBase);
	if (address >= actualBase) {
		uintptr_t offset = address - actualBase;
		if (offset < exec.imageSize) {
			return address;
		}
	}
	const uintptr_t preferredBase = static_cast<uintptr_t>(exec.preferredImageBase);
	if (address >= preferredBase) {
		return actualBase + (address - preferredBase);
	}
	return static_cast<uintptr_t>(static_cast<intptr_t>(address) + exec.relocationDelta);
}

void allocateModuleTlsForThread(wibo::ModuleInfo &module, TIB *tib) {
	if (!tib) {
		return;
	}
	auto &info = module.tlsInfo;
	if (!info.hasTls || info.index == wibo::tls::kInvalidTlsIndex || info.index >= kTlsSlotCount) {
		return;
	}
	if (info.threadAllocations.find(tib) != info.threadAllocations.end()) {
		return;
	}
	void *block = nullptr;
	const size_t allocationSize = info.allocationSize;
	if (allocationSize > 0) {
		block = std::malloc(allocationSize);
		if (!block) {
			DEBUG_LOG("  allocateModuleTlsForThread: failed to allocate %zu bytes for %s\n", allocationSize,
					  module.originalName.c_str());
			return;
		}
		std::memset(block, 0, allocationSize);
		if (info.templateData && info.templateSize > 0) {
			std::memcpy(block, info.templateData, info.templateSize);
		}
	}
	info.threadAllocations.emplace(tib, block);
	if (!wibo::tls::setValue(tib, info.index, block)) {
		DEBUG_LOG("  allocateModuleTlsForThread: failed to publish TLS pointer for %s (index %u)\n",
				  module.originalName.c_str(), info.index);
	}
}

void freeModuleTlsForThread(wibo::ModuleInfo &module, TIB *tib) {
	if (!tib) {
		return;
	}
	auto &info = module.tlsInfo;
	if (!info.hasTls) {
		return;
	}
	auto it = info.threadAllocations.find(tib);
	if (it == info.threadAllocations.end()) {
		return;
	}
	void *block = it->second;
	info.threadAllocations.erase(it);
	if (info.index < kTlsSlotCount && wibo::tls::getValue(tib, info.index) == block) {
		if (!wibo::tls::setValue(tib, info.index, nullptr)) {
			DEBUG_LOG("  freeModuleTlsForThread: failed to clear TLS pointer for %s (index %u)\n",
					  module.originalName.c_str(), info.index);
		}
	}
	if (block) {
		std::free(block);
	}
}

void runModuleTlsCallbacks(wibo::ModuleInfo &module, DWORD reason) {
	if (!module.tlsInfo.hasTls || module.tlsInfo.callbacks.empty()) {
		return;
	}
	TIB *tib = wibo::getThreadTibForHost();
	if (!tib) {
		return;
	}
	GUEST_CONTEXT_GUARD(tib);
	using TlsCallback = void(WIN_FUNC *)(void *, DWORD, void *);
	for (void *callbackAddr : module.tlsInfo.callbacks) {
		if (!callbackAddr) {
			continue;
		}
		auto callback = reinterpret_cast<TlsCallback>(callbackAddr);
		callback(module.handle, reason, nullptr);
	}
}

std::optional<std::filesystem::path> combineAndFind(const std::filesystem::path &directory,
													const std::string &filename) {
	if (filename.empty()) {
		return std::nullopt;
	}
	if (directory.empty()) {
		return std::nullopt;
	}
	return files::findCaseInsensitiveFile(directory, filename);
}

std::vector<std::filesystem::path> collectSearchDirectories(ModuleRegistry &reg, bool alteredSearchPath) {
	std::vector<std::filesystem::path> dirs;
	std::unordered_set<std::string> seen;

	auto addDirectory = [&](const std::filesystem::path &dir) {
		if (dir.empty())
			return;
		std::error_code ec;
		auto canonical = std::filesystem::weakly_canonical(dir, ec);
		if (ec) {
			canonical = std::filesystem::absolute(dir, ec);
		}
		if (ec)
			return;
		if (!std::filesystem::exists(canonical, ec) || ec)
			return;
		std::string key = stringToLower(canonical.string());
		if (seen.insert(key).second) {
			dirs.push_back(canonical);
		}
	};

	if (!wibo::guestExecutablePath.empty()) {
		auto parent = wibo::guestExecutablePath.parent_path();
		if (!parent.empty()) {
			addDirectory(parent);
		}
	}

	if (reg.dllDirectory.has_value()) {
		addDirectory(*reg.dllDirectory);
	}

	if (!alteredSearchPath) {
		addDirectory(std::filesystem::current_path());
	}

	const auto addFromEnv = [&](const char *envVar) {
		if (const char *envPath = std::getenv(envVar)) {
			std::string pathList = envPath;
			size_t start = 0;
			while (start <= pathList.size()) {
				size_t end = pathList.find_first_of(":;", start);
				if (end == std::string::npos) {
					end = pathList.size();
				}
				if (end > start) {
					auto piece = pathList.substr(start, end - start);
					if (!piece.empty()) {
						auto candidate = files::pathFromWindows(piece.c_str());
						if (!candidate.empty()) {
							addDirectory(candidate);
						} else {
							addDirectory(std::filesystem::path(piece));
						}
					}
				}
				if (end == pathList.size()) {
					break;
				}
				start = end + 1;
			}
		}
	};

	addFromEnv("WIBO_PATH");
	addFromEnv("WINEPATH"); // Wine compatibility

	return dirs;
}

std::optional<std::filesystem::path> resolveModuleOnDisk(ModuleRegistry &reg, const std::string &requestedName,
														 bool alteredSearchPath) {
	ParsedModuleName parsed = parseModuleName(requestedName);
	auto names = candidateModuleNames(parsed);

	if (!parsed.directory.empty()) {
		for (const auto &candidate : names) {
			auto combined = parsed.directory + "\\" + candidate;
			auto posixPath = files::pathFromWindows(combined.c_str());
			if (!posixPath.empty()) {
				auto resolved = files::findCaseInsensitiveFile(std::filesystem::path(posixPath).parent_path(),
															   std::filesystem::path(posixPath).filename().string());
				if (resolved) {
					return files::canonicalPath(*resolved);
				}
			}
		}
		return std::nullopt;
	}

	auto dirs = collectSearchDirectories(reg, alteredSearchPath);
	for (const auto &dir : dirs) {
		for (const auto &candidate : names) {
			auto resolved = combineAndFind(dir, candidate);
			if (resolved) {
				return files::canonicalPath(*resolved);
			}
		}
	}

	return std::nullopt;
}

std::string storageKeyForPath(const std::filesystem::path &path) {
	return normalizeAlias(files::pathToWindows(files::canonicalPath(path)));
}

std::string storageKeyForBuiltin(const std::string &normalizedName) { return normalizedName; }

wibo::ModuleInfo *findByAlias(ModuleRegistry &reg, const std::string &alias) {
	auto it = reg.modulesByAlias.find(alias);
	if (it != reg.modulesByAlias.end()) {
		return it->second;
	}
	return nullptr;
}

void registerAlias(ModuleRegistry &reg, const std::string &alias, wibo::ModuleInfo *info) {
	if (alias.empty() || !info) {
		return;
	}
	auto it = reg.modulesByAlias.find(alias);
	if (it == reg.modulesByAlias.end()) {
		reg.modulesByAlias[alias] = info;
		return;
	}
	if (reg.pinnedAliases.count(alias)) {
		return;
	}
	// Prefer externally loaded modules over built-ins when both are present.
	if (it->second && it->second->moduleStub != nullptr && info->moduleStub == nullptr) {
		reg.modulesByAlias[alias] = info;
	}
}

void registerBuiltinModule(ModuleRegistry &reg, const wibo::ModuleStub *module) {
	if (!module) {
		return;
	}
	wibo::ModulePtr entry = std::make_shared<wibo::ModuleInfo>();
	entry->handle = entry.get();
	entry->moduleStub = module;
	entry->refCount = UINT_MAX;
	entry->originalName = module->names[0] ? module->names[0] : "";
	entry->normalizedName = normalizedBaseKey(parseModuleName(entry->originalName));
	entry->exportsInitialized = true;
	auto storageKey = storageKeyForBuiltin(entry->normalizedName);
	auto raw = entry.get();
	reg.modulesByKey[storageKey] = std::move(entry);

	reg.builtinAliasLists[module] = {};
	auto &aliasList = reg.builtinAliasLists[module];
	const bool pinModule = (module == &lib_lmgr);
	if (pinModule) {
		reg.pinnedModules.insert(raw);
	}
	for (size_t i = 0; module->names[i]; ++i) {
		std::string alias = normalizeAlias(module->names[i]);
		aliasList.push_back(alias);
		if (pinModule) {
			reg.pinnedAliases.insert(alias);
		}
		registerAlias(reg, alias, raw);
		reg.builtinAliasMap[alias] = raw;
		ParsedModuleName parsed = parseModuleName(module->names[i]);
		std::string baseAlias = normalizedBaseKey(parsed);
		if (baseAlias != alias) {
			aliasList.push_back(baseAlias);
			if (pinModule) {
				reg.pinnedAliases.insert(baseAlias);
			}
			registerAlias(reg, baseAlias, raw);
			reg.builtinAliasMap[baseAlias] = raw;
		}
	}
}

BOOL callDllMain(wibo::ModuleInfo &info, DWORD reason, LPVOID reserved) {
	if (&info == wibo::mainModule) {
		return TRUE;
	}
	if (!info.executable) {
		return TRUE;
	}
	void *entry = info.executable->entryPoint;
	if (!entry) {
		return TRUE;
	}

	// Reset last error
	wibo::lastError = ERROR_SUCCESS;

	using DllMainFunc = BOOL(WIN_FUNC *)(HMODULE, DWORD, LPVOID);
	auto dllMain = reinterpret_cast<DllMainFunc>(entry);

	auto invokeWithGuestTIB = [&](DWORD callReason, LPVOID callReserved, bool force) -> BOOL {
		if (!force) {
			if (callReason == DLL_PROCESS_DETACH) {
				if (!info.processAttachCalled || !info.processAttachSucceeded) {
					return TRUE;
				}
			}
			if (callReason == DLL_THREAD_ATTACH || callReason == DLL_THREAD_DETACH) {
				if (!info.processAttachCalled || !info.processAttachSucceeded || !info.threadNotificationsEnabled) {
					return TRUE;
				}
			}
		}

		DEBUG_LOG("  callDllMain: invoking DllMain(%p, %u, %p) for %s\n",
				  reinterpret_cast<HMODULE>(info.executable->imageBase), callReason, callReserved,
				  info.normalizedName.c_str());

		BOOL result = TRUE;
		if (!wibo::tibSelector) {
			result = dllMain(reinterpret_cast<HMODULE>(info.executable->imageBase), callReason, callReserved);
		} else {
			TIB *tib = wibo::getThreadTibForHost();
			GUEST_CONTEXT_GUARD(tib);
			result = dllMain(reinterpret_cast<HMODULE>(info.executable->imageBase), callReason, callReserved);
		}
		DEBUG_LOG("  callDllMain: %s DllMain returned %d\n", info.normalizedName.c_str(), result);
		return result;
	};

	switch (reason) {
	case DLL_PROCESS_ATTACH: {
		if (info.processAttachCalled) {
			return info.processAttachSucceeded ? TRUE : FALSE;
		}
		info.processAttachCalled = true;
		info.processAttachSucceeded = false;
		BOOL result = invokeWithGuestTIB(DLL_PROCESS_ATTACH, reserved, true);
		if (!result) {
			invokeWithGuestTIB(DLL_PROCESS_DETACH, nullptr, true);
			return FALSE;
		}
		info.processAttachSucceeded = true;
		return TRUE;
	}
	case DLL_PROCESS_DETACH: {
		BOOL result = invokeWithGuestTIB(DLL_PROCESS_DETACH, reserved, false);
		if (info.processAttachSucceeded) {
			info.processAttachSucceeded = false;
		}
		return result;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		return invokeWithGuestTIB(reason, reserved, false);
	default:
		break;
	}

	return TRUE;
}

void registerExternalModuleAliases(ModuleRegistry &reg, const std::string &requestedName,
								   const std::filesystem::path &resolvedPath, wibo::ModuleInfo *info) {
	ParsedModuleName parsed = parseModuleName(requestedName);
	registerAlias(reg, normalizedBaseKey(parsed), info);
	registerAlias(reg, normalizeAlias(requestedName), info);
	registerAlias(reg, storageKeyForPath(resolvedPath), info);
}

wibo::ModuleInfo *moduleFromAddress(ModuleRegistry &reg, void *addr) {
	if (!addr)
		return nullptr;
	for (auto &pair : reg.modulesByKey) {
		wibo::ModuleInfo *info = pair.second.get();
		if (!info || !info->executable)
			continue;
		const auto *base = static_cast<const uint8_t *>(info->executable->imageBase);
		size_t size = info->executable->imageSize;
		if (!base || size == 0)
			continue;
		const auto *ptr = static_cast<const uint8_t *>(addr);
		if (ptr >= base && ptr < base + size) {
			return info;
		}
	}
	return nullptr;
}

bool shouldDeliverThreadNotifications(const wibo::ModuleInfo &info) {
	if (&info == wibo::mainModule) {
		return false;
	}
	if (info.moduleStub != nullptr) {
		return false;
	}
	if (!info.executable) {
		return false;
	}
	if (!info.processAttachCalled || !info.processAttachSucceeded) {
		return false;
	}
	if (!info.threadNotificationsEnabled) {
		return false;
	}
	return true;
}

void ensureExportsInitialized(wibo::ModuleInfo &info) {
	if (info.moduleStub || info.exportsInitialized)
		return;
	if (!info.executable)
		return;
	auto *exe = info.executable.get();
	if (!exe->exportDirectoryRVA || !exe->exportDirectorySize) {
		info.exportsInitialized = true;
		return;
	}

	auto *dir = exe->fromRVA<PEExportDirectory>(exe->exportDirectoryRVA);
	info.exportOrdinalBase = dir->base;
	uint32_t functionCount = dir->numberOfFunctions;
	info.exportsByOrdinal.assign(functionCount, nullptr);
	if (functionCount) {
		auto *functions = exe->fromRVA<uint32_t>(dir->addressOfFunctions);
		for (uint32_t i = 0; i < functionCount; ++i) {
			uint32_t rva = functions[i];
			if (!rva) {
				continue;
			}
			if (rva >= exe->exportDirectoryRVA && rva < exe->exportDirectoryRVA + exe->exportDirectorySize) {
				const char *forward = exe->fromRVA<const char>(rva);
				info.exportsByOrdinal[i] =
					reinterpret_cast<void *>(resolveMissingFuncName(info.originalName.c_str(), forward));
			} else {
				info.exportsByOrdinal[i] = exe->fromRVA<void>(rva);
			}
		}
	}

	uint32_t nameCount = dir->numberOfNames;
	if (nameCount) {
		auto *names = exe->fromRVA<uint32_t>(dir->addressOfNames);
		auto *ordinals = exe->fromRVA<uint16_t>(dir->addressOfNameOrdinals);
		for (uint32_t i = 0; i < nameCount; ++i) {
			uint16_t index = ordinals[i];
			auto ordinal = static_cast<uint16_t>(dir->base + index);
			if (index < info.exportsByOrdinal.size()) {
				const char *namePtr = exe->fromRVA<const char>(names[i]);
				info.exportNameToOrdinal[std::string(namePtr)] = ordinal;
			}
		}
	}
	info.exportsInitialized = true;
}

} // namespace

namespace wibo {

void initializeModuleRegistry() { registry(); }

ModuleInfo *registerProcessModule(std::unique_ptr<Executable> executable, std::filesystem::path resolvedPath,
								  std::string originalName) {
	if (!executable) {
		return nullptr;
	}

	if (originalName.empty() && !resolvedPath.empty()) {
		originalName = resolvedPath.filename().string();
	}

	ParsedModuleName parsed = parseModuleName(originalName);
	std::string normalizedName = normalizedBaseKey(parsed);

	ModulePtr info = std::make_unique<ModuleInfo>();
	info->handle = executable->imageBase; // Use image base as handle for main module
	info->moduleStub = nullptr;
	info->originalName = std::move(originalName);
	info->normalizedName = std::move(normalizedName);
	info->resolvedPath = std::move(resolvedPath);
	info->executable = std::move(executable);
	info->refCount = UINT_MAX;

	ModuleInfo *raw = info.get();

	std::string storageKey;
	if (!raw->resolvedPath.empty()) {
		storageKey = storageKeyForPath(raw->resolvedPath);
	} else if (!raw->normalizedName.empty()) {
		storageKey = storageKeyForBuiltin(raw->normalizedName);
	}
	if (storageKey.empty()) {
		storageKey = normalizeAlias(raw->originalName);
	}

	auto reg = registry();
	reg->modulesByKey[storageKey] = std::move(info);

	if (!raw->resolvedPath.empty()) {
		registerExternalModuleAliases(*reg, raw->originalName, raw->resolvedPath, raw);
	} else {
		registerAlias(*reg, normalizeAlias(raw->originalName), raw);
		std::string baseAlias = normalizedBaseKey(parsed);
		if (baseAlias != raw->originalName) {
			registerAlias(*reg, baseAlias, raw);
		}
	}

	ensureExportsInitialized(*raw);

	auto pinAlias = [&](const std::string &alias) {
		if (!alias.empty()) {
			reg->pinnedAliases.insert(alias);
		}
	};
	reg->pinnedModules.insert(raw);
	pinAlias(storageKey);
	pinAlias(normalizeAlias(raw->originalName));
	pinAlias(normalizedName);

	return raw;
}

void shutdownModuleRegistry() {
	auto reg = registry();
	for (auto &pair : reg->modulesByKey) {
		ModuleInfo *info = pair.second.get();
		if (!info || info->moduleStub) {
			continue;
		}
		runPendingOnExit(*info);
		if (info->tlsInfo.hasTls) {
			runModuleTlsCallbacks(*info, TLS_PROCESS_DETACH);
		}
		if (info->processAttachCalled && info->processAttachSucceeded) {
			callDllMain(*info, DLL_PROCESS_DETACH, reinterpret_cast<LPVOID>(1));
		}
		releaseModuleTls(*info);
	}
	reg->modulesByKey.clear();
	reg->modulesByAlias.clear();
	reg->dllDirectory.reset();
	reg->initialized = false;
	reg->onExitTables.clear();
}

ModuleInfo *moduleInfoFromHandle(HMODULE module) {
	if (isMainModule(module)) {
		return wibo::mainModule;
	}
	if (!module) {
		return nullptr;
	}
	auto reg = registry();
	for (auto &pair : reg->modulesByKey) {
		wibo::ModuleInfo *info = pair.second.get();
		if (!info) {
			continue;
		}
		if (info->handle == module) {
			return info;
		}
		if (info->executable && info->executable->imageBase == module) {
			return info;
		}
	}
	return nullptr;
}

void setDllDirectoryOverride(const std::filesystem::path &path) {
	auto canonical = files::canonicalPath(path);
	auto reg = registry();
	reg->dllDirectory = canonical;
}

void clearDllDirectoryOverride() {
	auto reg = registry();
	reg->dllDirectory.reset();
}

std::optional<std::filesystem::path> dllDirectoryOverride() {
	auto reg = registry();
	return reg->dllDirectory;
}

ModuleInfo *moduleInfoFromAddress(void *addr) {
	if (!addr) {
		return nullptr;
	}
	auto reg = registry();
	return moduleFromAddress(*reg, addr);
}

void registerOnExitTable(void *table) {
	if (!table)
		return;
	auto reg = registry();
	if (reg->onExitTables.find(table) == reg->onExitTables.end()) {
		if (auto *info = moduleFromAddress(*reg, table)) {
			reg->onExitTables[table] = info;
		}
	}
}

void addOnExitFunction(void *table, void (*func)()) {
	if (!func)
		return;
	auto reg = registry();
	ModuleInfo *info = nullptr;
	auto it = reg->onExitTables.find(table);
	if (it != reg->onExitTables.end()) {
		info = it->second;
	} else if (table) {
		info = moduleFromAddress(*reg, table);
		if (info)
			reg->onExitTables[table] = info;
	}
	if (info) {
		info->onExitFunctions.push_back(reinterpret_cast<void *>(func));
	}
}

void runPendingOnExit(ModuleInfo &info) {
	TIB *tib = wibo::getThreadTibForHost();
	for (auto it = info.onExitFunctions.rbegin(); it != info.onExitFunctions.rend(); ++it) {
		auto fn = reinterpret_cast<void (*)()>(*it);
		if (fn) {
			GUEST_CONTEXT_GUARD(tib);
			fn();
		}
	}
	info.onExitFunctions.clear();
}

bool initializeModuleTls(ModuleInfo &module) {
	if (module.tlsInfo.hasTls) {
		return true;
	}
	if (!module.executable) {
		return true;
	}
	Executable &exec = *module.executable;
	if (exec.tlsDirectoryRVA == 0 || exec.tlsDirectorySize < sizeof(ImageTlsDirectory32)) {
		return true;
	}
	auto tlsDirectory = exec.fromRVA<ImageTlsDirectory32>(exec.tlsDirectoryRVA);
	if (!tlsDirectory) {
		return false;
	}

	auto &info = module.tlsInfo;
	info.templateSize = (tlsDirectory->EndAddressOfRawData > tlsDirectory->StartAddressOfRawData)
							? tlsDirectory->EndAddressOfRawData - tlsDirectory->StartAddressOfRawData
							: 0;
	info.zeroFillSize = tlsDirectory->SizeOfZeroFill;
	info.characteristics = tlsDirectory->Characteristics;
	info.templateData = reinterpret_cast<uint8_t *>(resolveModuleAddress(exec, tlsDirectory->StartAddressOfRawData));
	info.indexLocation = reinterpret_cast<DWORD *>(resolveModuleAddress(exec, tlsDirectory->AddressOfIndex));
	info.callbacks.clear();
	uintptr_t callbacksArray = resolveModuleAddress(exec, tlsDirectory->AddressOfCallBacks);
	if (callbacksArray) {
		auto callbackPtr = reinterpret_cast<uintptr_t *>(callbacksArray);
		while (callbackPtr && *callbackPtr) {
			info.callbacks.push_back(reinterpret_cast<void *>(resolveModuleAddress(exec, *callbackPtr)));
			++callbackPtr;
		}
	}
	info.allocationSize = info.templateSize + info.zeroFillSize;
	DWORD index = tls::reserveSlot();
	if (index == tls::kInvalidTlsIndex) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return false;
	}
	info.index = index;
	if (info.indexLocation) {
		*info.indexLocation = index;
	}
	info.hasTls = true;
	info.threadAllocations.clear();

	if (TIB *tib = wibo::getThreadTibForHost()) {
		allocateModuleTlsForThread(module, tib);
	}
	runModuleTlsCallbacks(module, TLS_PROCESS_ATTACH);
	wibo::lastError = ERROR_SUCCESS;
	return true;
}

void releaseModuleTls(ModuleInfo &module) {
	if (!module.tlsInfo.hasTls) {
		return;
	}
	for (auto &[tib, block] : module.tlsInfo.threadAllocations) {
		if (tib && module.tlsInfo.index < kTlsSlotCount && wibo::tls::getValue(tib, module.tlsInfo.index) == block) {
			wibo::tls::setValue(tib, module.tlsInfo.index, nullptr);
		}
		if (block) {
			std::free(block);
		}
	}
	module.tlsInfo.threadAllocations.clear();
	if (module.tlsInfo.index != wibo::tls::kInvalidTlsIndex) {
		wibo::tls::releaseSlot(module.tlsInfo.index);
	}
	module.tlsInfo = wibo::ModuleTlsInfo{};
}

void executeOnExitTable(void *table) {
	auto reg = registry();
	ModuleInfo *info = nullptr;
	if (table) {
		auto it = reg->onExitTables.find(table);
		if (it != reg->onExitTables.end()) {
			info = it->second;
			reg->onExitTables.erase(it);
		} else {
			info = moduleFromAddress(*reg, table);
		}
	}
	if (info) {
		runPendingOnExit(*info);
	}
}

void notifyDllThreadAttach() {
	auto reg = registry();
	std::vector<wibo::ModuleInfo *> targets;
	targets.reserve(reg->modulesByKey.size());
	for (auto &pair : reg->modulesByKey) {
		wibo::ModuleInfo *info = pair.second.get();
		if (info && shouldDeliverThreadNotifications(*info)) {
			targets.push_back(info);
		}
	}
	TIB *tib = wibo::getThreadTibForHost();
	for (wibo::ModuleInfo *info : targets) {
		if (info && info->tlsInfo.hasTls && tib) {
			allocateModuleTlsForThread(*info, tib);
			runModuleTlsCallbacks(*info, TLS_THREAD_ATTACH);
		}
	}
	for (wibo::ModuleInfo *info : targets) {
		callDllMain(*info, DLL_THREAD_ATTACH, nullptr);
	}
	wibo::lastError = ERROR_SUCCESS;
}

void notifyDllThreadDetach() {
	auto reg = registry();
	std::vector<wibo::ModuleInfo *> targets;
	targets.reserve(reg->modulesByKey.size());
	for (auto &pair : reg->modulesByKey) {
		wibo::ModuleInfo *info = pair.second.get();
		if (info && shouldDeliverThreadNotifications(*info)) {
			targets.push_back(info);
		}
	}
	TIB *tib = wibo::getThreadTibForHost();
	for (auto it = targets.rbegin(); it != targets.rend(); ++it) {
		if (*it && (*it)->tlsInfo.hasTls && tib) {
			runModuleTlsCallbacks(**it, TLS_THREAD_DETACH);
		}
	}
	for (auto it = targets.rbegin(); it != targets.rend(); ++it) {
		callDllMain(**it, DLL_THREAD_DETACH, nullptr);
	}
	for (auto it = targets.rbegin(); it != targets.rend(); ++it) {
		if (*it && (*it)->tlsInfo.hasTls && tib) {
			freeModuleTlsForThread(**it, tib);
		}
	}
	wibo::lastError = ERROR_SUCCESS;
}

BOOL disableThreadNotifications(ModuleInfo *info) {
	if (!info) {
		return FALSE;
	}
	auto reg = registry();
	(void)reg;
	info->threadNotificationsEnabled = false;
	return TRUE;
}

ModuleInfo *findLoadedModule(const char *name) {
	if (!name || *name == '\0') {
		return wibo::mainModule;
	}
	auto reg = registry();
	ParsedModuleName parsed = parseModuleName(name);
	std::string alias = normalizedBaseKey(parsed);
	ModuleInfo *info = findByAlias(*reg, alias);
	if (!info) {
		info = findByAlias(*reg, normalizeAlias(name));
	}
	return info;
}

ModuleInfo *loadModule(const char *dllName) {
	if (!dllName || *dllName == '\0') {
		lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	std::string requested(dllName);
	DEBUG_LOG("loadModule(%s)\n", requested.c_str());

	auto reg = registry();

	ParsedModuleName parsed = parseModuleName(requested);

	DWORD diskError = ERROR_SUCCESS;

	auto tryLoadExternal = [&](const std::filesystem::path &path) -> ModuleInfo * {
		std::string key = storageKeyForPath(path);
		auto existingIt = reg->modulesByKey.find(key);
		if (existingIt != reg->modulesByKey.end()) {
			ModuleInfo *info = existingIt->second.get();
			if (info->refCount != UINT_MAX) {
				info->refCount++;
			}
			registerExternalModuleAliases(*reg, requested, files::canonicalPath(path), info);
			return info;
		}
		reg.lock.unlock();

		DEBUG_LOG("  loading external module from %s\n", path.c_str());
		FILE *file = fopen(path.c_str(), "rb");
		if (!file) {
			perror("loadModule");
			reg.lock.lock();
			diskError = ERROR_MOD_NOT_FOUND;
			return nullptr;
		}

		auto executable = std::make_unique<Executable>();
		if (!executable->loadPE(file, true)) {
			DEBUG_LOG("  loadPE failed for %s\n", path.c_str());
			fclose(file);
			reg.lock.lock();
			diskError = ERROR_BAD_EXE_FORMAT;
			return nullptr;
		}
		fclose(file);

		ModulePtr info = std::make_unique<ModuleInfo>();
		info->handle = info.get();
		info->moduleStub = nullptr;
		info->originalName = requested;
		info->normalizedName = normalizedBaseKey(parsed);
		info->resolvedPath = files::canonicalPath(path);
		info->executable = std::move(executable);
		info->refCount = 1;

		reg.lock.lock();
		ModuleInfo *raw = info.get();
		reg->modulesByKey[key] = std::move(info);
		registerExternalModuleAliases(*reg, requested, raw->resolvedPath, raw);
		reg.lock.unlock();
		ensureExportsInitialized(*raw);
		if (!raw->executable->resolveImports()) {
			DEBUG_LOG("  resolveImports failed for %s\n", raw->originalName.c_str());
			reg.lock.lock();
			reg->modulesByKey.erase(key);
			diskError = wibo::lastError;
			return nullptr;
		}
		if (!initializeModuleTls(*raw)) {
			DEBUG_LOG("  initializeModuleTls failed for %s\n", raw->originalName.c_str());
			reg.lock.lock();
			reg->modulesByKey.erase(key);
			diskError = wibo::lastError;
			return nullptr;
		}
		reg.lock.lock();
		if (!callDllMain(*raw, DLL_PROCESS_ATTACH, nullptr)) {
			DEBUG_LOG("  DllMain failed for %s\n", raw->originalName.c_str());
			releaseModuleTls(*raw);
			runPendingOnExit(*raw);
			for (auto it = reg->onExitTables.begin(); it != reg->onExitTables.end();) {
				if (it->second == raw) {
					it = reg->onExitTables.erase(it);
				} else {
					++it;
				}
			}
			for (auto it = reg->modulesByAlias.begin(); it != reg->modulesByAlias.end();) {
				if (it->second == raw) {
					it = reg->modulesByAlias.erase(it);
				} else {
					++it;
				}
			}
			reg->pinnedModules.erase(raw);
			reg->modulesByKey.erase(key);
			diskError = ERROR_DLL_INIT_FAILED;
			wibo::lastError = ERROR_DLL_INIT_FAILED;
			return nullptr;
		}
		return raw;
	};

	auto resolveAndLoadExternal = [&]() -> ModuleInfo * {
		auto resolvedPath = resolveModuleOnDisk(*reg, requested, false);
		if (!resolvedPath) {
			DEBUG_LOG("  module not found on disk\n");
			diskError = ERROR_MOD_NOT_FOUND;
			return nullptr;
		}
		return tryLoadExternal(*resolvedPath);
	};

	std::string alias = normalizedBaseKey(parsed);
	ModuleInfo *existing = findByAlias(*reg, alias);
	if (!existing) {
		existing = findByAlias(*reg, normalizeAlias(requested));
	}
	if (existing) {
		DEBUG_LOG("  found existing module alias %s (builtin=%d)\n", alias.c_str(), existing->moduleStub != nullptr);
		if (existing->moduleStub == nullptr) {
			if (existing->refCount != UINT_MAX) {
				existing->refCount++;
			}
			DEBUG_LOG("  returning existing external module %s\n", existing->originalName.c_str());
			return existing;
		}
		bool pinned = reg->pinnedModules.count(existing) != 0;
		if (!pinned) {
			if (ModuleInfo *external = resolveAndLoadExternal()) {
				DEBUG_LOG("  replaced builtin module %s with external copy\n", requested.c_str());
				return external;
			} else if (diskError != ERROR_MOD_NOT_FOUND) {
				lastError = diskError;
				return nullptr;
			}
		}
		DEBUG_LOG("  returning builtin module %s\n", existing->originalName.c_str());
		return existing;
	}

	if (ModuleInfo *external = resolveAndLoadExternal()) {
		DEBUG_LOG("  loaded external module %s\n", requested.c_str());
		return external;
	} else if (diskError != ERROR_MOD_NOT_FOUND) {
		lastError = diskError;
		return nullptr;
	}

	auto fallbackAlias = normalizedBaseKey(parsed);
	ModuleInfo *builtin = nullptr;
	auto builtinIt = reg->builtinAliasMap.find(fallbackAlias);
	if (builtinIt != reg->builtinAliasMap.end()) {
		builtin = builtinIt->second;
	}
	if (!builtin) {
		builtinIt = reg->builtinAliasMap.find(normalizeAlias(requested));
		if (builtinIt != reg->builtinAliasMap.end()) {
			builtin = builtinIt->second;
		}
	}
	if (builtin && builtin->moduleStub != nullptr) {
		DEBUG_LOG("  falling back to builtin module %s\n", builtin->originalName.c_str());
		return builtin;
	}

	lastError = (diskError != ERROR_SUCCESS) ? diskError : ERROR_MOD_NOT_FOUND;
	return nullptr;
}

void freeModule(ModuleInfo *info) {
	auto reg = registry();
	if (!info || info->refCount == UINT_MAX) {
		return;
	}
	if (info->refCount == 0) {
		return;
	}
	info->refCount--;
	if (info->refCount == 0) {
		for (auto it = reg->onExitTables.begin(); it != reg->onExitTables.end();) {
			if (it->second == info) {
				it = reg->onExitTables.erase(it);
			} else {
				++it;
			}
		}
		runPendingOnExit(*info);
		if (info->tlsInfo.hasTls) {
			runModuleTlsCallbacks(*info, TLS_PROCESS_DETACH);
		}
		callDllMain(*info, DLL_PROCESS_DETACH, nullptr);
		releaseModuleTls(*info);
		std::string key = info->resolvedPath.empty() ? storageKeyForBuiltin(info->normalizedName)
													 : storageKeyForPath(info->resolvedPath);
		reg->modulesByKey.erase(key);
		for (auto it = reg->modulesByAlias.begin(); it != reg->modulesByAlias.end();) {
			if (it->second == info) {
				it = reg->modulesByAlias.erase(it);
			} else {
				++it;
			}
		}
	}
}

void *resolveFuncByName(ModuleInfo *info, const char *funcName) {
	if (!info) {
		return nullptr;
	}
	if (info->moduleStub && info->moduleStub->byName) {
		void *func = info->moduleStub->byName(funcName);
		if (func) {
			return func;
		}
	}
	ensureExportsInitialized(*info);
	if (!info->moduleStub) {
		auto it = info->exportNameToOrdinal.find(funcName);
		if (it != info->exportNameToOrdinal.end()) {
			return resolveFuncByOrdinal(info, it->second);
		}
	}
	return reinterpret_cast<void *>(resolveMissingFuncName(info->originalName.c_str(), funcName));
}

void *resolveFuncByOrdinal(ModuleInfo *info, uint16_t ordinal) {
	if (!info) {
		return nullptr;
	}
	if (info->moduleStub && info->moduleStub->byOrdinal) {
		void *func = info->moduleStub->byOrdinal(ordinal);
		if (func) {
			return func;
		}
	}
	if (!info->moduleStub) {
		ensureExportsInitialized(*info);
		if (!info->exportsByOrdinal.empty() && ordinal >= info->exportOrdinalBase) {
			auto index = static_cast<size_t>(ordinal - info->exportOrdinalBase);
			if (index < info->exportsByOrdinal.size()) {
				void *addr = info->exportsByOrdinal[index];
				if (addr) {
					return addr;
				}
			}
		}
	}
	return reinterpret_cast<void *>(resolveMissingFuncOrdinal(info->originalName.c_str(), ordinal));
}

void *resolveMissingImportByName(const char *dllName, const char *funcName) {
	const char *safeDll = dllName ? dllName : "";
	const char *safeFunc = funcName ? funcName : "";
	[[maybe_unused]] auto reg = registry();
	return reinterpret_cast<void *>(resolveMissingFuncName(safeDll, safeFunc));
}

void *resolveMissingImportByOrdinal(const char *dllName, uint16_t ordinal) {
	const char *safeDll = dllName ? dllName : "";
	[[maybe_unused]] auto reg = registry();
	return reinterpret_cast<void *>(resolveMissingFuncOrdinal(safeDll, ordinal));
}

Executable *executableFromModule(HMODULE module) {
	ModuleInfo *info = moduleInfoFromHandle(module);
	if (!info) {
		return nullptr;
	}
	if (!info->executable && !info->resolvedPath.empty()) {
		FILE *file = fopen(info->resolvedPath.c_str(), "rb");
		if (!file) {
			perror("executableFromModule");
			return nullptr;
		}
		auto executable = std::make_unique<Executable>();
		if (!executable->loadPE(file, false)) {
			DEBUG_LOG("executableFromModule: failed to load %s\n", info->resolvedPath.c_str());
			fclose(file);
			return nullptr;
		}
		fclose(file);
		info->executable = std::move(executable);
	}
	return info->executable.get();
}

std::unordered_map<std::string, ModulePtr> allLoadedModules() {
	auto reg = registry();
	return reg->modulesByKey;
}

} // namespace wibo
