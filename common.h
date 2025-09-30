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

#define TRUE 1
#define FALSE 0

#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_NO_MORE_FILES 18
#define ERROR_READ_FAULT 30
#define ERROR_HANDLE_EOF 38
#define ERROR_NOT_SUPPORTED 50
#define ERROR_INVALID_PARAMETER 87
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define ERROR_BUFFER_OVERFLOW 111
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_NONE_MAPPED 1332
#define ERROR_RESOURCE_DATA_NOT_FOUND 1812
#define ERROR_RESOURCE_TYPE_NOT_FOUND 1813
#define ERROR_RESOURCE_NAME_NOT_FOUND 1814
#define ERROR_RESOURCE_LANG_NOT_FOUND 1815
#define ERROR_MOD_NOT_FOUND 126
#define ERROR_PROC_NOT_FOUND 127
#define ERROR_NEGATIVE_SEEK 131
#define ERROR_BAD_EXE_FORMAT 193
#define ERROR_ALREADY_EXISTS 183
#define ERROR_NOT_OWNER 288

#define STILL_ACTIVE 259

#define TIME_ZONE_ID_UNKNOWN 0
#define TIME_ZONE_ID_STANDARD 1
#define TIME_ZONE_ID_DAYLIGHT 2

#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

typedef int NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002)
#define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define STATUS_UNEXPECTED_IO_ERROR ((NTSTATUS)0xC00000E9)

typedef int HRESULT;
#define S_OK ((HRESULT)0x00000000)

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
