#pragma once

#include "common.h"
#include "entry.h"
#include "tls.h"
#include "types.h"

#include <optional>
#include <span>
#include <unordered_map>

namespace wibo {

using ResolveByName = void *(*)(const char *);
using ResolveByOrdinal = void *(*)(uint16_t);

struct ResourceIdentifier;
struct ResourceLocation;

struct ModuleStub {
	const char **names;
	ResolveByName byName = nullptr;
	ResolveByOrdinal byOrdinal = nullptr;
	std::span<const uint8_t> dllData{};
};

class Executable {
  public:
	struct SectionInfo {
		uintptr_t base = 0;
		size_t size = 0;
		DWORD protect = PAGE_NOACCESS;
		DWORD characteristics = 0;
	};

	Executable() = default;
	~Executable();

	bool loadPE(FILE *file, bool exec);
	bool loadPE(std::span<const uint8_t> image, bool exec);
	bool resolveImports();
	bool findResource(const ResourceIdentifier &type, const ResourceIdentifier &name, std::optional<uint16_t> language,
					  ResourceLocation &out) const;

	template <typename T> T *fromRVA(uint32_t rva) const { return (T *)(rva + (uint8_t *)imageBase); }

	void *imageBase = nullptr;
	size_t imageSize = 0;
	void *entryPoint = nullptr;
	void *rsrcBase = nullptr;
	uint32_t rsrcSize = 0;
	uintptr_t preferredImageBase = 0;
	intptr_t relocationDelta = 0;
	uint32_t exportDirectoryRVA = 0;
	uint32_t exportDirectorySize = 0;
	uint32_t relocationDirectoryRVA = 0;
	uint32_t relocationDirectorySize = 0;
	uint32_t importDirectoryRVA = 0;
	uint32_t importDirectorySize = 0;
	uint32_t delayImportDirectoryRVA = 0;
	uint32_t delayImportDirectorySize = 0;
	uint32_t tlsDirectoryRVA = 0;
	uint32_t tlsDirectorySize = 0;
	bool execMapped = false;
	bool importsResolved = false;
	bool importsResolving = false;
	bool sectionsProtected = false;
	std::vector<SectionInfo> sections;
};

struct ModuleTlsInfo {
	bool hasTls = false;
	DWORD index = tls::kInvalidTlsIndex;
	DWORD loaderIndex = tls::kInvalidTlsIndex;
	DWORD *indexLocation = nullptr;
	uint8_t *templateData = nullptr;
	size_t templateSize = 0;
	size_t zeroFillSize = 0;
	uint32_t characteristics = 0;
	size_t allocationSize = 0;
	std::vector<PIMAGE_TLS_CALLBACK> callbacks;
	std::unordered_map<TEB *, GUEST_PTR> threadAllocations;
};

struct ModuleInfo {
	// Windows-style handle to the module. For the main module, this is the image base.
	// For other modules, this is a pointer to the ModuleInfo structure.
	HMODULE handle;
	// Original name used to load the module
	std::string originalName;
	// Normalized module name
	std::string normalizedName;
	// Full path to the loaded module
	std::filesystem::path resolvedPath;
	// Pointer to the built-in module, nullptr if loaded from file
	const wibo::ModuleStub *moduleStub = nullptr;
	// Loaded PE executable
	std::unique_ptr<wibo::Executable> executable;
	// Reference count, or UINT_MAX for built-in modules
	unsigned int refCount = 0;
	bool processAttachCalled = false;
	bool processAttachSucceeded = false;
	bool threadNotificationsEnabled = true;
	uint32_t exportOrdinalBase = 0;
	std::vector<void *> exportsByOrdinal;
	std::unordered_map<std::string, uint16_t> exportNameToOrdinal;
	bool exportsInitialized = false;
	ModuleTlsInfo tlsInfo;
};
extern ModuleInfo *mainModule;

using ModulePtr = std::shared_ptr<wibo::ModuleInfo>;

void initializeModuleRegistry();
void shutdownModuleRegistry();
ModuleInfo *moduleInfoFromHandle(HMODULE module);
void setDllDirectoryOverride(const std::filesystem::path &path);
void clearDllDirectoryOverride();
std::optional<std::filesystem::path> dllDirectoryOverride();
ModuleInfo *findLoadedModule(const char *name);
void notifyDllThreadAttach();
void notifyDllThreadDetach();
BOOL disableThreadNotifications(ModuleInfo *info);
std::unordered_map<std::string, ModulePtr> allLoadedModules();
bool initializeModuleTls(ModuleInfo &module);
void releaseModuleTls(ModuleInfo &module);

ModuleInfo *loadModule(const char *name);
void freeModule(ModuleInfo *info);
void *resolveFuncByName(ModuleInfo *info, const char *funcName);
void *resolveFuncByOrdinal(ModuleInfo *info, uint16_t ordinal);
void *resolveMissingImportByName(const char *dllName, const char *funcName);
void *resolveMissingImportByOrdinal(const char *dllName, uint16_t ordinal);

ModuleInfo *registerProcessModule(std::unique_ptr<Executable> executable, std::filesystem::path resolvedPath,
								  std::string originalName);
Executable *executableFromModule(HMODULE module);
ModuleInfo *moduleInfoFromAddress(void *addr);

/**
 * HMODULE will be `nullptr` or `mainModule->imageBase` if it's the main module,
 * otherwise it will be a pointer to a `wibo::ModuleInfo`.
 */
inline bool isMainModule(HMODULE hModule) {
	return hModule == NO_HANDLE || (mainModule && mainModule->executable &&
									reinterpret_cast<void *>(hModule) == mainModule->executable->imageBase);
}

} // namespace wibo
