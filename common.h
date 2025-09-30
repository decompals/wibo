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
#include <unordered_map>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// On Windows, the incoming stack is aligned to a 4 byte boundary.
// force_align_arg_pointer will realign the stack to match GCC's 16 byte alignment.
#define WIN_ENTRY __attribute__((force_align_arg_pointer, callee_pop_aggregate_return(0)))
#define WIN_FUNC WIN_ENTRY __attribute__((stdcall))
#define DEBUG_LOG(...) \
	do { \
		if (wibo::debugEnabled) { \
			wibo::debug_log(__VA_ARGS__); \
		} \
	} while (0)

#ifndef NDEBUG
#define VERBOSE_LOG(...) DEBUG_LOG(__VA_ARGS__)
#else
#define VERBOSE_LOG(...) ((void)0)
#endif

typedef void *HANDLE;
typedef void *HMODULE;
typedef void *PVOID;
typedef void *LPVOID;
typedef void *FARPROC;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef int32_t LONG;
typedef LONG *PLONG;
typedef uint32_t ULONG;
typedef ULONG *PULONG;
typedef int64_t LARGE_INTEGER;
typedef LARGE_INTEGER *PLARGE_INTEGER;
typedef uintptr_t ULONG_PTR;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef uint16_t *LPWSTR;
typedef const uint16_t *LPCWSTR;
typedef int BOOL;
typedef BOOL *PBOOL;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
typedef size_t SIZE_T;
typedef SIZE_T *PSIZE_T;
typedef unsigned char BYTE;

typedef struct _OVERLAPPED {
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	union {
		struct {
			DWORD Offset;
			DWORD OffsetHigh;
		};
		PVOID Pointer;
	};
	HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

#define TRUE 1
#define FALSE 0

#define STILL_ACTIVE 259

#define TIME_ZONE_ID_UNKNOWN 0
#define TIME_ZONE_ID_STANDARD 1
#define TIME_ZONE_ID_DAYLIGHT 2

#define FILE_FLAG_OVERLAPPED 0x40000000
#define FILE_FLAG_NO_BUFFERING 0x20000000

#define MAX_PATH (260)

namespace wibo {
	extern uint32_t lastError;
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
		const char** names;
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

		bool findResource(const ResourceIdentifier &type, const ResourceIdentifier &name,
						  std::optional<uint16_t> language, ResourceLocation &out) const;

		template <typename T>
		T *fromRVA(uintptr_t rva) const {
			return (T *) (rva + (uint8_t *) imageBase);
		}

		template <typename T>
		T *fromRVA(T *rva) const {
			return fromRVA<T>((uintptr_t) rva);
		}
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
