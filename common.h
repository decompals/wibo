#pragma once

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

// On Windows, the incoming stack is aligned to a 4 byte boundary.
// force_align_arg_pointer will realign the stack to match GCC's 16 byte alignment.
#ifdef __clang__
#define WIN_ENTRY __attribute__((force_align_arg_pointer))
#else
#define WIN_ENTRY __attribute__((force_align_arg_pointer, callee_pop_aggregate_return(0)))
#endif
#define WIN_FUNC WIN_ENTRY __attribute__((stdcall))

#define DEBUG_LOG(...)                                                                                                 \
	do {                                                                                                               \
		if (wibo::debugEnabled) {                                                                                      \
			wibo::debug_log(__VA_ARGS__);                                                                              \
		}                                                                                                              \
	} while (0)
#ifndef NDEBUG
#define VERBOSE_LOG(...) DEBUG_LOG(__VA_ARGS__)
#else
#define VERBOSE_LOG(...) ((void)0)
#endif

using HANDLE = void *;
using HMODULE = void *;
using HGLOBAL = HANDLE;
using HLOCAL = HANDLE;
using HRSRC = HANDLE;
using LPHANDLE = HANDLE *;
using PVOID = void *;
using LPVOID = void *;
using LPCVOID = const void *;
using FARPROC = void *;
using WORD = uint16_t;
using LPWORD = WORD *;
using LANGID = WORD;
using DWORD = uint32_t;
using PDWORD = DWORD *;
using LPDWORD = DWORD *;
using LONG = int32_t;
using PLONG = LONG *;
using ULONG = uint32_t;
using PULONG = ULONG *;
using LARGE_INTEGER = int64_t;
using PLARGE_INTEGER = LARGE_INTEGER *;
using ULONG_PTR = uintptr_t;
using UINT_PTR = uintptr_t;
using DWORD_PTR = ULONG_PTR;
using PDWORD_PTR = DWORD_PTR *;
using SHORT = int16_t;
using LPSTR = char *;
using LPCSTR = const char *;
using LPCCH = const char *;
using LPWSTR = uint16_t *;
using LPCWSTR = const uint16_t *;
using LPCWCH = const uint16_t *;
using WCHAR = uint16_t;
using LPCH = char *;
using LPWCH = uint16_t *;
using BOOL = int;
using PBOOL = BOOL *;
using LPBOOL = BOOL *;
using UCHAR = unsigned char;
using PUCHAR = UCHAR *;
using SIZE_T = size_t;
using PSIZE_T = SIZE_T *;
using BYTE = unsigned char;
using BOOLEAN = unsigned char;
using UINT = unsigned int;
using HKEY = void *;
using PHKEY = HKEY *;
using REGSAM = DWORD;
using LSTATUS = LONG;
using LCID = DWORD;
using LCTYPE = DWORD;

constexpr BOOL TRUE = 1;
constexpr BOOL FALSE = 0;

constexpr DWORD STILL_ACTIVE = 259;

constexpr DWORD FILE_FLAG_OVERLAPPED = 0x40000000;
constexpr DWORD FILE_FLAG_NO_BUFFERING = 0x20000000;

constexpr DWORD STD_INPUT_HANDLE = ((DWORD)-10);
constexpr DWORD STD_OUTPUT_HANDLE = ((DWORD)-11);
constexpr DWORD STD_ERROR_HANDLE = ((DWORD)-12);

namespace wibo {
extern thread_local uint32_t lastError;
extern char **argv;
extern int argc;
extern std::filesystem::path guestExecutablePath;
extern std::string executableName;
extern std::string commandLine;
extern std::vector<uint16_t> commandLineW;
extern bool debugEnabled;
extern unsigned int debugIndent;
extern uint16_t tibSelector;

void debug_log(const char *fmt, ...);

using ResolveByName = void *(*)(const char *);
using ResolveByOrdinal = void *(*)(uint16_t);
struct Module {
	const char **names;
	ResolveByName byName;
	ResolveByOrdinal byOrdinal;
};
struct ModuleInfo;
void initializeModuleRegistry();
void shutdownModuleRegistry();
ModuleInfo *moduleInfoFromHandle(HMODULE module);
void setDllDirectoryOverride(const std::filesystem::path &path);
void clearDllDirectoryOverride();
std::optional<std::filesystem::path> dllDirectoryOverride();
ModuleInfo *findLoadedModule(const char *name);
void registerOnExitTable(void *table);
void addOnExitFunction(void *table, void (*func)());
void executeOnExitTable(void *table);
void runPendingOnExit(ModuleInfo &info);

ModuleInfo *loadModule(const char *name);
void freeModule(ModuleInfo *info);
void *resolveFuncByName(ModuleInfo *info, const char *funcName);
void *resolveFuncByOrdinal(ModuleInfo *info, uint16_t ordinal);
void *resolveMissingImportByName(const char *dllName, const char *funcName);
void *resolveMissingImportByOrdinal(const char *dllName, uint16_t ordinal);

struct ResourceIdentifier {
	ResourceIdentifier() : isString(false), id(0) {}
	static ResourceIdentifier fromID(uint32_t value) {
		ResourceIdentifier ident;
		ident.isString = false;
		ident.id = value;
		return ident;
	}
	static ResourceIdentifier fromString(std::u16string value) {
		ResourceIdentifier ident;
		ident.isString = true;
		ident.name = std::move(value);
		return ident;
	}
	bool isString;
	uint32_t id;
	std::u16string name;
};

struct ResourceLocation {
	const void *dataEntry = nullptr;
	const void *data = nullptr;
	uint32_t size = 0;
	uint16_t language = 0;
};

struct ImageResourceDataEntry {
	uint32_t offsetToData;
	uint32_t size;
	uint32_t codePage;
	uint32_t reserved;
};

struct Executable {
	Executable() = default;
	~Executable();
	bool loadPE(FILE *file, bool exec);
	bool resolveImports();

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
	bool execMapped = false;
	bool importsResolved = false;
	bool importsResolving = false;

	bool findResource(const ResourceIdentifier &type, const ResourceIdentifier &name, std::optional<uint16_t> language,
					  ResourceLocation &out) const;
	template <typename T> T *fromRVA(uintptr_t rva) const { return (T *)(rva + (uint8_t *)imageBase); }
	template <typename T> T *fromRVA(T *rva) const { return fromRVA<T>((uintptr_t)rva); }
};

extern ModuleInfo *mainModule;
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
	const wibo::Module *module = nullptr;
	// Loaded PE executable
	std::unique_ptr<wibo::Executable> executable;
	// Reference count, or UINT_MAX for built-in modules
	unsigned int refCount = 0;
	bool processAttachCalled = false;
	bool processAttachSucceeded = false;
	uint32_t exportOrdinalBase = 0;
	std::vector<void *> exportsByOrdinal;
	std::unordered_map<std::string, uint16_t> exportNameToOrdinal;
	bool exportsInitialized = false;
	std::vector<void *> onExitFunctions;
};

ModuleInfo *registerProcessModule(std::unique_ptr<Executable> executable, std::filesystem::path resolvedPath,
								  std::string originalName);
Executable *executableFromModule(HMODULE module);

/**
 * HMODULE will be `nullptr` or `mainModule->imageBase` if it's the main module,
 * otherwise it will be a pointer to a `wibo::ModuleInfo`.
 */
inline bool isMainModule(HMODULE hModule) {
	return hModule == nullptr || hModule == reinterpret_cast<HMODULE>(mainModule) ||
		   (mainModule && mainModule->executable && hModule == mainModule->executable->imageBase);
}
} // namespace wibo
