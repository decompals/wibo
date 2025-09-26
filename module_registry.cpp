#include "common.h"
#include "files.h"
#include "strutil.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern const wibo::Module lib_advapi32;
extern const wibo::Module lib_bcrypt;
extern const wibo::Module lib_crt;
extern const wibo::Module lib_kernel32;
extern const wibo::Module lib_lmgr;
extern const wibo::Module lib_mscoree;
extern const wibo::Module lib_msvcrt;
extern const wibo::Module lib_ntdll;
extern const wibo::Module lib_rpcrt4;
extern const wibo::Module lib_ole32;
extern const wibo::Module lib_user32;
extern const wibo::Module lib_vcruntime;
extern const wibo::Module lib_version;

namespace {

constexpr DWORD DLL_PROCESS_DETACH = 0;
constexpr DWORD DLL_PROCESS_ATTACH = 1;

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

#define FOR_256_3(a, b, c, d) FOR_ITER((a << 6 | b << 4 | c << 2 | d))
#define FOR_256_2(a, b)                                                                                                \
	FOR_256_3(a, b, 0, 0)                                                                                              \
	FOR_256_3(a, b, 0, 1)                                                                                              \
	FOR_256_3(a, b, 0, 2)                                                                                              \
	FOR_256_3(a, b, 0, 3) FOR_256_3(a, b, 1, 0) FOR_256_3(a, b, 1, 1) FOR_256_3(a, b, 1, 2) FOR_256_3(a, b, 1, 3)      \
		FOR_256_3(a, b, 2, 0) FOR_256_3(a, b, 2, 1) FOR_256_3(a, b, 2, 2) FOR_256_3(a, b, 2, 3) FOR_256_3(a, b, 3, 0)  \
			FOR_256_3(a, b, 3, 1) FOR_256_3(a, b, 3, 2) FOR_256_3(a, b, 3, 3)
#define FOR_256                                                                                                        \
	FOR_256_2(0, 0)                                                                                                    \
	FOR_256_2(0, 1)                                                                                                    \
	FOR_256_2(0, 2)                                                                                                    \
	FOR_256_2(0, 3) FOR_256_2(1, 0) FOR_256_2(1, 1) FOR_256_2(1, 2) FOR_256_2(1, 3) FOR_256_2(2, 0) FOR_256_2(2, 1)    \
		FOR_256_2(2, 2) FOR_256_2(2, 3) FOR_256_2(3, 0) FOR_256_2(3, 1) FOR_256_2(3, 2) FOR_256_2(3, 3)

static int stubIndex = 0;
static char stubDlls[0x100][0x100];
static char stubFuncNames[0x100][0x100];

static void stubBase(int index) {
	printf("Unhandled function %s (%s)\n", stubFuncNames[index], stubDlls[index]);
	exit(1);
}

void (*stubFuncs[0x100])(void) = {
#define FOR_ITER(i) []() { stubBase(i); },
	FOR_256
#undef FOR_ITER
};

#undef FOR_256_3
#undef FOR_256_2
#undef FOR_256

void *resolveMissingFuncName(const char *dllName, const char *funcName) {
	DEBUG_LOG("Missing function: %s (%s)\n", dllName, funcName);
	assert(stubIndex < 0x100);
	assert(strlen(dllName) < 0x100);
	assert(strlen(funcName) < 0x100);
	strcpy(stubFuncNames[stubIndex], funcName);
	strcpy(stubDlls[stubIndex], dllName);
	return (void *)stubFuncs[stubIndex++];
}

void *resolveMissingFuncOrdinal(const char *dllName, uint16_t ordinal) {
	char buf[16];
	sprintf(buf, "%d", ordinal);
	return resolveMissingFuncName(dllName, buf);
}

} // namespace

namespace {

using ModulePtr = std::unique_ptr<wibo::ModuleInfo>;

struct ModuleRegistry {
	std::recursive_mutex mutex;
	std::unordered_map<std::string, ModulePtr> modulesByKey;
	std::unordered_map<std::string, wibo::ModuleInfo *> modulesByAlias;
	std::optional<std::filesystem::path> dllDirectory;
	bool initialized = false;
	std::unordered_map<void *, wibo::ModuleInfo *> onExitTables;
	std::unordered_map<const wibo::Module *, std::vector<std::string>> builtinAliasLists;
	std::unordered_map<std::string, wibo::ModuleInfo *> builtinAliasMap;
};

ModuleRegistry &registry() {
	static ModuleRegistry reg;
	return reg;
}

std::string toLowerCopy(const std::string &value) {
	std::string out = value;
	std::transform(out.begin(), out.end(), out.begin(),
				   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return out;
}

std::string normalizeAlias(const std::string &value) {
	std::string out = value;
	std::replace(out.begin(), out.end(), '/', '\\');
	std::transform(out.begin(), out.end(), out.begin(),
				   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
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
		return std::string();
	}
	std::string base = parsed.base;
	if (!parsed.hasExtension && !parsed.endsWithDot) {
		base += ".dll";
	}
	return normalizeAlias(base);
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

std::vector<std::filesystem::path> collectSearchDirectories(bool alteredSearchPath) {
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
		std::string key = toLowerCopy(canonical.string());
		if (seen.insert(key).second) {
			dirs.push_back(canonical);
		}
	};

	auto &reg = registry();

	if (wibo::argv && wibo::argc > 0 && wibo::argv[0]) {
		std::filesystem::path mainBinary = std::filesystem::absolute(wibo::argv[0]);
		if (mainBinary.has_parent_path()) {
			addDirectory(mainBinary.parent_path());
		}
	}

	if (reg.dllDirectory.has_value()) {
		addDirectory(*reg.dllDirectory);
	}

	addDirectory(files::pathFromWindows("Z:/Windows/System32"));
	addDirectory(files::pathFromWindows("Z:/Windows"));

	if (!alteredSearchPath) {
		addDirectory(std::filesystem::current_path());
	}

	if (const char *envPath = std::getenv("PATH")) {
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
					std::filesystem::path candidate(piece);
					if (piece.find(':') != std::string::npos || piece.find('\\') != std::string::npos) {
						auto converted = files::pathFromWindows(piece.c_str());
						if (!converted.empty()) {
							candidate = converted;
						}
					}
					addDirectory(candidate);
				}
			}
			if (end == pathList.size()) {
				break;
			}
			start = end + 1;
		}
	}

	return dirs;
}
std::optional<std::filesystem::path> resolveModuleOnDisk(const std::string &requestedName, bool alteredSearchPath) {
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

	auto dirs = collectSearchDirectories(alteredSearchPath);
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

wibo::ModuleInfo *findByAlias(const std::string &alias) {
	auto &reg = registry();
	auto it = reg.modulesByAlias.find(alias);
	if (it != reg.modulesByAlias.end()) {
		return it->second;
	}
	return nullptr;
}

void registerAlias(const std::string &alias, wibo::ModuleInfo *info) {
	if (alias.empty() || !info) {
		return;
	}
	auto &reg = registry();
	auto it = reg.modulesByAlias.find(alias);
	if (it == reg.modulesByAlias.end()) {
		reg.modulesByAlias[alias] = info;
		return;
	}
	// Prefer externally loaded modules over built-ins when both are present.
	if (it->second && it->second->module != nullptr && info->module == nullptr) {
		reg.modulesByAlias[alias] = info;
	}
}

void registerBuiltinModule(const wibo::Module *module) {
	if (!module) {
		return;
	}
	ModulePtr entry = std::make_unique<wibo::ModuleInfo>();
	entry->module = module;
	entry->refCount = UINT_MAX;
	entry->originalName = module->names[0] ? module->names[0] : "";
	entry->normalizedName = normalizedBaseKey(parseModuleName(entry->originalName));
	entry->exportsInitialized = true;
	auto storageKey = storageKeyForBuiltin(entry->normalizedName);
	auto raw = entry.get();
	auto &reg = registry();
	reg.modulesByKey[storageKey] = std::move(entry);

	reg.builtinAliasLists[module] = {};
	auto &aliasList = reg.builtinAliasLists[module];
	for (size_t i = 0; module->names[i]; ++i) {
		std::string alias = normalizeAlias(module->names[i]);
		aliasList.push_back(alias);
		registerAlias(alias, raw);
		reg.builtinAliasMap[alias] = raw;
		ParsedModuleName parsed = parseModuleName(module->names[i]);
		std::string baseAlias = normalizedBaseKey(parsed);
		if (baseAlias != alias) {
			aliasList.push_back(baseAlias);
			registerAlias(baseAlias, raw);
			reg.builtinAliasMap[baseAlias] = raw;
		}
	}
}

void callDllMain(wibo::ModuleInfo &info, DWORD reason) {
	if (!info.entryPoint || info.module) {
		return;
	}
	using DllMainFunc = BOOL(WIN_FUNC *)(HMODULE, DWORD, LPVOID);
	auto dllMain = reinterpret_cast<DllMainFunc>(info.entryPoint);
	if (!dllMain) {
		return;
	}

	auto invokeWithGuestTIB = [&](DWORD callReason) -> BOOL {
		if (!wibo::tibSelector) {
			return dllMain(reinterpret_cast<HMODULE>(info.imageBase), callReason, nullptr);
		}

		uint16_t previousSegment = 0;
		asm volatile("mov %%fs, %0" : "=r"(previousSegment));
		asm volatile("movw %0, %%fs" : : "r"(wibo::tibSelector) : "memory");
		BOOL result = dllMain(reinterpret_cast<HMODULE>(info.imageBase), callReason, nullptr);
		asm volatile("movw %0, %%fs" : : "r"(previousSegment) : "memory");
		return result;
	};

	if (reason == DLL_PROCESS_ATTACH) {
		if (info.processAttachCalled) {
			return;
		}
		info.processAttachCalled = true;
		BOOL result = invokeWithGuestTIB(reason);
		info.processAttachSucceeded = result != 0;
	} else if (reason == DLL_PROCESS_DETACH) {
		if (info.processAttachCalled && info.processAttachSucceeded) {
			invokeWithGuestTIB(reason);
		}
	}
}

void ensureInitialized() {
	auto &reg = registry();
	if (reg.initialized) {
		return;
	}
	reg.initialized = true;

	const wibo::Module *builtins[] = {
		&lib_advapi32, &lib_bcrypt, &lib_crt,	 &lib_kernel32,	 &lib_lmgr,	   &lib_mscoree, &lib_msvcrt,
		&lib_ntdll,	   &lib_ole32,	&lib_rpcrt4,	&lib_user32, &lib_vcruntime, &lib_version, nullptr,
	};

	for (const wibo::Module **module = builtins; *module; ++module) {
		registerBuiltinModule(*module);
	}
}

void registerExternalModuleAliases(const std::string &requestedName, const std::filesystem::path &resolvedPath,
								   wibo::ModuleInfo *info) {
	ParsedModuleName parsed = parseModuleName(requestedName);
	registerAlias(normalizedBaseKey(parsed), info);
	registerAlias(normalizeAlias(requestedName), info);
	registerAlias(storageKeyForPath(resolvedPath), info);
}

wibo::ModuleInfo *moduleFromAddress(void *addr) {
	if (!addr)
		return nullptr;
	auto &reg = registry();
	for (auto &pair : reg.modulesByKey) {
		wibo::ModuleInfo *info = pair.second.get();
		if (!info)
			continue;
		uint8_t *base = nullptr;
		size_t size = 0;
		if (info->imageBase && info->imageSize) {
			base = static_cast<uint8_t *>(info->imageBase);
			size = info->imageSize;
		} else if (info->executable) {
			base = static_cast<uint8_t *>(info->executable->imageBuffer);
			size = info->executable->imageSize;
		}
		if (!base || size == 0)
			continue;
		uint8_t *ptr = static_cast<uint8_t *>(addr);
		if (ptr >= base && ptr < base + size) {
			return info;
		}
	}
	return nullptr;
}

void ensureExportsInitialized(wibo::ModuleInfo &info) {
	if (info.module || info.exportsInitialized)
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
				info.exportsByOrdinal[i] = resolveMissingFuncName(info.originalName.c_str(), forward);
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
			uint16_t ordinal = static_cast<uint16_t>(dir->base + index);
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

void initializeModuleRegistry() {
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	ensureInitialized();
}

void shutdownModuleRegistry() {
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	for (auto &pair : registry().modulesByKey) {
		ModuleInfo *info = pair.second.get();
		if (!info || info->module) {
			continue;
		}
		runPendingOnExit(*info);
		if (info->processAttachCalled && info->processAttachSucceeded) {
			callDllMain(*info, DLL_PROCESS_DETACH);
		}
	}
	registry().modulesByKey.clear();
	registry().modulesByAlias.clear();
	registry().dllDirectory.reset();
	registry().initialized = false;
	registry().onExitTables.clear();
}

ModuleInfo *moduleInfoFromHandle(HMODULE module) { return static_cast<ModuleInfo *>(module); }

void setDllDirectoryOverride(const std::filesystem::path &path) {
	auto canonical = files::canonicalPath(path);
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	registry().dllDirectory = canonical;
}

void clearDllDirectoryOverride() {
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	registry().dllDirectory.reset();
}

std::optional<std::filesystem::path> dllDirectoryOverride() {
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	return registry().dllDirectory;
}

void registerOnExitTable(void *table) {
	if (!table)
		return;
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	ensureInitialized();
	auto &reg = registry();
	if (reg.onExitTables.find(table) == reg.onExitTables.end()) {
		if (auto *info = moduleFromAddress(table)) {
			reg.onExitTables[table] = info;
		}
	}
}

void addOnExitFunction(void *table, void (*func)()) {
	if (!func)
		return;
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	auto &reg = registry();
	ModuleInfo *info = nullptr;
	auto it = reg.onExitTables.find(table);
	if (it != reg.onExitTables.end()) {
		info = it->second;
	} else if (table) {
		info = moduleFromAddress(table);
		if (info)
			reg.onExitTables[table] = info;
	}
	if (info) {
		info->onExitFunctions.push_back(reinterpret_cast<void *>(func));
	}
}

void runPendingOnExit(ModuleInfo &info) {
	for (auto it = info.onExitFunctions.rbegin(); it != info.onExitFunctions.rend(); ++it) {
		auto fn = reinterpret_cast<void (*)(void)>(*it);
		if (fn) {
			fn();
		}
	}
	info.onExitFunctions.clear();
}

void executeOnExitTable(void *table) {
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	auto &reg = registry();
	ModuleInfo *info = nullptr;
	if (table) {
		auto it = reg.onExitTables.find(table);
		if (it != reg.onExitTables.end()) {
			info = it->second;
			reg.onExitTables.erase(it);
		} else {
			info = moduleFromAddress(table);
		}
	}
	if (info) {
		runPendingOnExit(*info);
	}
}

HMODULE findLoadedModule(const char *name) {
	if (!name) {
		return nullptr;
	}
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	ensureInitialized();
	ParsedModuleName parsed = parseModuleName(name);
	std::string alias = normalizedBaseKey(parsed);
	ModuleInfo *info = findByAlias(alias);
	if (!info) {
		info = findByAlias(normalizeAlias(name));
	}
	return info;
}

HMODULE loadModule(const char *dllName) {
	if (!dllName) {
		lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	std::string requested(dllName);
	DEBUG_LOG("loadModule(%s)\n", requested.c_str());

	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	ensureInitialized();

	ParsedModuleName parsed = parseModuleName(requested);

	auto &reg = registry();
	DWORD diskError = ERROR_SUCCESS;

	auto tryLoadExternal = [&](const std::filesystem::path &path) -> ModuleInfo * {
		std::string key = storageKeyForPath(path);
		auto existingIt = reg.modulesByKey.find(key);
		if (existingIt != reg.modulesByKey.end()) {
			ModuleInfo *info = existingIt->second.get();
			if (info->refCount != UINT_MAX) {
				info->refCount++;
			}
			registerExternalModuleAliases(requested, files::canonicalPath(path), info);
			return info;
		}

		FILE *file = fopen(path.c_str(), "rb");
		if (!file) {
			perror("loadModule");
			diskError = ERROR_MOD_NOT_FOUND;
			return nullptr;
		}

		auto executable = std::make_unique<Executable>();
		if (!executable->loadPE(file, true)) {
			DEBUG_LOG("  loadPE failed for %s\n", path.c_str());
			fclose(file);
			diskError = ERROR_BAD_EXE_FORMAT;
			return nullptr;
		}
		fclose(file);

		ModulePtr info = std::make_unique<ModuleInfo>();
		info->module = nullptr;
		info->originalName = requested;
		info->normalizedName = normalizedBaseKey(parsed);
		info->resolvedPath = files::canonicalPath(path);
		info->executable = std::move(executable);
		info->entryPoint = info->executable->entryPoint;
		info->imageBase = info->executable->imageBuffer;
		info->imageSize = info->executable->imageSize;
		info->refCount = 1;
		info->dataFile = false;
		info->dontResolveReferences = false;

		ModuleInfo *raw = info.get();
		reg.modulesByKey[key] = std::move(info);
		registerExternalModuleAliases(requested, raw->resolvedPath, raw);
		ensureExportsInitialized(*raw);
		callDllMain(*raw, DLL_PROCESS_ATTACH);
		return raw;
	};

	auto resolveAndLoadExternal = [&]() -> ModuleInfo * {
		auto resolvedPath = resolveModuleOnDisk(requested, false);
		if (!resolvedPath) {
			DEBUG_LOG("  module not found on disk\n");
			return nullptr;
		}
		return tryLoadExternal(*resolvedPath);
	};

	std::string alias = normalizedBaseKey(parsed);
	ModuleInfo *existing = findByAlias(alias);
	if (!existing) {
		existing = findByAlias(normalizeAlias(requested));
	}
	if (existing) {
		DEBUG_LOG("  found existing module alias %s (builtin=%d)\n", alias.c_str(), existing->module != nullptr);
		if (existing->module == nullptr) {
			if (existing->refCount != UINT_MAX) {
				existing->refCount++;
			}
			DEBUG_LOG("  returning existing external module %s\n", existing->originalName.c_str());
			lastError = ERROR_SUCCESS;
			return existing;
		}
		if (ModuleInfo *external = resolveAndLoadExternal()) {
			DEBUG_LOG("  replaced builtin module %s with external copy\n", requested.c_str());
			lastError = ERROR_SUCCESS;
			return external;
		}
		lastError = ERROR_SUCCESS;
		DEBUG_LOG("  returning builtin module %s\n", existing->originalName.c_str());
		return existing;
	}

	if (ModuleInfo *external = resolveAndLoadExternal()) {
		DEBUG_LOG("  loaded external module %s\n", requested.c_str());
		lastError = ERROR_SUCCESS;
		return external;
	}

	auto fallbackAlias = normalizedBaseKey(parsed);
	ModuleInfo *builtin = nullptr;
	auto builtinIt = reg.builtinAliasMap.find(fallbackAlias);
	if (builtinIt != reg.builtinAliasMap.end()) {
		builtin = builtinIt->second;
	}
	if (!builtin) {
		builtinIt = reg.builtinAliasMap.find(normalizeAlias(requested));
		if (builtinIt != reg.builtinAliasMap.end()) {
			builtin = builtinIt->second;
		}
	}
	if (builtin && builtin->module != nullptr) {
		DEBUG_LOG("  falling back to builtin module %s\n", builtin->originalName.c_str());
		lastError = (diskError != ERROR_SUCCESS) ? diskError : ERROR_SUCCESS;
		return builtin;
	}

	lastError = (diskError != ERROR_SUCCESS) ? diskError : ERROR_MOD_NOT_FOUND;
	return nullptr;
}

void freeModule(HMODULE module) {
	if (!module) {
		return;
	}
	std::lock_guard<std::recursive_mutex> lock(registry().mutex);
	ModuleInfo *info = moduleInfoFromHandle(module);
	if (!info || info->refCount == UINT_MAX) {
		return;
	}
	if (info->refCount == 0) {
		return;
	}
	info->refCount--;
	if (info->refCount == 0) {
		auto &reg = registry();
		for (auto it = reg.onExitTables.begin(); it != reg.onExitTables.end();) {
			if (it->second == info) {
				it = reg.onExitTables.erase(it);
			} else {
				++it;
			}
		}
		runPendingOnExit(*info);
		callDllMain(*info, DLL_PROCESS_DETACH);
		std::string key = info->resolvedPath.empty() ? storageKeyForBuiltin(info->normalizedName)
													 : storageKeyForPath(info->resolvedPath);
		reg.modulesByKey.erase(key);
		for (auto it = reg.modulesByAlias.begin(); it != reg.modulesByAlias.end();) {
			if (it->second == info) {
				it = reg.modulesByAlias.erase(it);
			} else {
				++it;
			}
		}
	}
}

void *resolveFuncByName(HMODULE module, const char *funcName) {
	ModuleInfo *info = moduleInfoFromHandle(module);
	if (!info) {
		return nullptr;
	}
	if (info->module && info->module->byName) {
		void *func = info->module->byName(funcName);
		if (func) {
			return func;
		}
	}
	ensureExportsInitialized(*info);
	if (!info->module) {
		auto it = info->exportNameToOrdinal.find(funcName);
		if (it != info->exportNameToOrdinal.end()) {
			return resolveFuncByOrdinal(module, it->second);
		}
	}
	return resolveMissingFuncName(info->originalName.c_str(), funcName);
}

void *resolveFuncByOrdinal(HMODULE module, uint16_t ordinal) {
	ModuleInfo *info = moduleInfoFromHandle(module);
	if (!info) {
		return nullptr;
	}
	if (info->module && info->module->byOrdinal) {
		void *func = info->module->byOrdinal(ordinal);
		if (func) {
			return func;
		}
	}
	if (!info->module) {
		ensureExportsInitialized(*info);
		if (!info->exportsByOrdinal.empty() && ordinal >= info->exportOrdinalBase) {
			size_t index = static_cast<size_t>(ordinal - info->exportOrdinalBase);
			if (index < info->exportsByOrdinal.size()) {
				void *addr = info->exportsByOrdinal[index];
				if (addr) {
					return addr;
				}
			}
		}
	}
	return resolveMissingFuncOrdinal(info->originalName.c_str(), ordinal);
}

Executable *executableFromModule(HMODULE module) {
	if (isMainModule(module)) {
		return mainModule;
	}
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

} // namespace wibo
