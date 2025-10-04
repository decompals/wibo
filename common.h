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
using PHANDLE = HANDLE *;
using HKL = HANDLE;
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
struct LUID {
	DWORD LowPart;
	LONG HighPart;
};
using PLUID = LUID *;
using LPLUID = LUID *;
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
using PSID = void *;
using REGSAM = DWORD;
using LSTATUS = LONG;
using LCID = DWORD;
using LCTYPE = DWORD;

constexpr BOOL TRUE = 1;
constexpr BOOL FALSE = 0;

constexpr DWORD STILL_ACTIVE = 259;

constexpr DWORD FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
constexpr DWORD FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
constexpr DWORD FILE_FLAG_NO_BUFFERING = 0x20000000;
constexpr DWORD FILE_FLAG_OVERLAPPED = 0x40000000;

constexpr DWORD STD_INPUT_HANDLE = ((DWORD)-10);
constexpr DWORD STD_OUTPUT_HANDLE = ((DWORD)-11);
constexpr DWORD STD_ERROR_HANDLE = ((DWORD)-12);

constexpr DWORD FILE_READ_DATA = 0x00000001;
constexpr DWORD FILE_LIST_DIRECTORY = 0x00000001;
constexpr DWORD FILE_WRITE_DATA = 0x00000002;
constexpr DWORD FILE_ADD_FILE = 0x00000002;
constexpr DWORD FILE_APPEND_DATA = 0x00000004;
constexpr DWORD FILE_ADD_SUBDIRECTORY = 0x00000004;
constexpr DWORD FILE_CREATE_PIPE_INSTANCE = 0x00000004;
constexpr DWORD FILE_READ_EA = 0x00000008;
constexpr DWORD FILE_WRITE_EA = 0x00000010;
constexpr DWORD FILE_EXECUTE = 0x00000020;
constexpr DWORD FILE_TRAVERSE = 0x00000020;
constexpr DWORD FILE_DELETE_CHILD = 0x00000040;
constexpr DWORD FILE_READ_ATTRIBUTES = 0x00000080;
constexpr DWORD FILE_WRITE_ATTRIBUTES = 0x00000100;

constexpr DWORD SYNCHRONIZE = 0x00100000;
constexpr DWORD DELETE = 0x00010000;

constexpr DWORD STANDARD_RIGHTS_READ = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_WRITE = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_EXECUTE = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_REQUIRED = 0x000f0000;
constexpr DWORD STANDARD_RIGHTS_ALL = 0x001f0000;

constexpr DWORD FILE_GENERIC_READ =
	STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
constexpr DWORD FILE_GENERIC_WRITE =
	STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
constexpr DWORD FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;
constexpr DWORD FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;

constexpr DWORD EVENT_ALL_ACCESS = 0x1F0003;
constexpr DWORD MUTEX_ALL_ACCESS = 0x1F0001;
constexpr DWORD SEMAPHORE_ALL_ACCESS = 0x1F0003;

constexpr DWORD GENERIC_READ = 0x80000000;
constexpr DWORD GENERIC_WRITE = 0x40000000;
constexpr DWORD GENERIC_EXECUTE = 0x20000000;
constexpr DWORD GENERIC_ALL = 0x10000000;

// Page protection constants
constexpr DWORD PAGE_NOACCESS = 0x01;
constexpr DWORD PAGE_READONLY = 0x02;
constexpr DWORD PAGE_READWRITE = 0x04;
constexpr DWORD PAGE_WRITECOPY = 0x08;
constexpr DWORD PAGE_EXECUTE = 0x10;
constexpr DWORD PAGE_EXECUTE_READ = 0x20;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
constexpr DWORD PAGE_GUARD = 0x100;
constexpr DWORD PAGE_NOCACHE = 0x200;
constexpr DWORD PAGE_WRITECOMBINE = 0x400;

// Allocation type and memory state constants
constexpr DWORD MEM_COMMIT = 0x00001000;
constexpr DWORD MEM_RESERVE = 0x00002000;
constexpr DWORD MEM_DECOMMIT = 0x00004000;
constexpr DWORD MEM_RELEASE = 0x00008000;
constexpr DWORD MEM_FREE = 0x00010000;
constexpr DWORD MEM_PRIVATE = 0x00020000;
constexpr DWORD MEM_MAPPED = 0x00040000;
constexpr DWORD MEM_RESET = 0x00080000;
constexpr DWORD MEM_TOP_DOWN = 0x00100000;
constexpr DWORD MEM_WRITE_WATCH = 0x00200000;
constexpr DWORD MEM_PHYSICAL = 0x00400000;
constexpr DWORD MEM_RESET_UNDO = 0x01000000;
constexpr DWORD MEM_LARGE_PAGES = 0x20000000;
constexpr DWORD MEM_COALESCE_PLACEHOLDERS = 0x00000001;
constexpr DWORD MEM_PRESERVE_PLACEHOLDER = 0x00000002;
constexpr DWORD MEM_IMAGE = 0x01000000;

// File mapping access flags
constexpr DWORD FILE_MAP_COPY = 0x00000001;
constexpr DWORD FILE_MAP_WRITE = 0x00000002;
constexpr DWORD FILE_MAP_READ = 0x00000004;
constexpr DWORD FILE_MAP_EXECUTE = 0x00000020;
constexpr DWORD FILE_MAP_ALL_ACCESS = 0x000f001f;

// File share modes
constexpr DWORD FILE_SHARE_READ = 0x00000001;
constexpr DWORD FILE_SHARE_WRITE = 0x00000002;
constexpr DWORD FILE_SHARE_DELETE = 0x00000004;

struct UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	uint16_t *Buffer;
};

struct RTL_USER_PROCESS_PARAMETERS {
	char Reserved1[16];
	void *Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
};

struct PEB {
	char Reserved1[2];
	char BeingDebugged;
	char Reserved2[1];
	void *Reserved3[2];
	void *Ldr;
	RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
	char Reserved4[104];
	void *Reserved5[52];
	void *PostProcessInitRoutine;
	char Reserved6[128];
	void *Reserved7[1];
	unsigned int SessionId;
};

struct TIB {
	void *sehFrame;
	void *stackBase;
	void *stackLimit;
	void *subSystemTib;
	void *fiberData;
	void *arbitraryDataSlot;
	TIB *tib;
	char reserved1[0x14];
	PEB *peb;
	char reserved2[0x1000];
};

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
extern int tibEntryNumber;
extern PEB *processPeb;

TIB *allocateTib();
void initializeTibStackInfo(TIB *tib);
bool installTibForCurrentThread(TIB *tib);
void destroyTib(TIB *tib);

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
void notifyDllThreadAttach();
void notifyDllThreadDetach();
BOOL disableThreadNotifications(ModuleInfo *info);

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

	struct SectionInfo {
		uintptr_t base = 0;
		size_t size = 0;
		DWORD protect = PAGE_NOACCESS;
		DWORD characteristics = 0;
	};

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
	std::vector<SectionInfo> sections;

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
	bool threadNotificationsEnabled = true;
	uint32_t exportOrdinalBase = 0;
	std::vector<void *> exportsByOrdinal;
	std::unordered_map<std::string, uint16_t> exportNameToOrdinal;
	bool exportsInitialized = false;
	std::vector<void *> onExitFunctions;
};

ModuleInfo *registerProcessModule(std::unique_ptr<Executable> executable, std::filesystem::path resolvedPath,
								  std::string originalName);
Executable *executableFromModule(HMODULE module);
ModuleInfo *moduleInfoFromAddress(void *addr);

/**
 * HMODULE will be `nullptr` or `mainModule->imageBase` if it's the main module,
 * otherwise it will be a pointer to a `wibo::ModuleInfo`.
 */
inline bool isMainModule(HMODULE hModule) {
	return hModule == nullptr || hModule == reinterpret_cast<HMODULE>(mainModule) ||
		   (mainModule && mainModule->executable && hModule == mainModule->executable->imageBase);
}
} // namespace wibo
