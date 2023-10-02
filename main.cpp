#include "common.h"
#include "files.h"
#include <asm/ldt.h>
#include <filesystem>
#include <errno.h>
#include <memory>
#include "strutil.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <iostream>
#include <fstream>
#include <vector>

uint32_t wibo::lastError = 0;
char** wibo::argv;
int wibo::argc;
char *wibo::executableName;
char *wibo::commandLine;
std::vector<uint16_t> wibo::commandLineW;
wibo::Executable *wibo::mainModule = 0;
bool wibo::debugEnabled = false;
unsigned int wibo::debugIndent = 0;

void wibo::debug_log(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (wibo::debugEnabled) {
		for (size_t i = 0; i < wibo::debugIndent; i++)
			fprintf(stderr, "\t");

		vfprintf(stderr, fmt, args);
	}

	va_end(args);
}

#define FOR_256_3(a, b, c, d) FOR_ITER((a << 6 | b << 4 | c << 2 | d))
#define FOR_256_2(a, b) \
	FOR_256_3(a, b, 0, 0) FOR_256_3(a, b, 0, 1) FOR_256_3(a, b, 0, 2) FOR_256_3(a, b, 0, 3) \
	FOR_256_3(a, b, 1, 0) FOR_256_3(a, b, 1, 1) FOR_256_3(a, b, 1, 2) FOR_256_3(a, b, 1, 3) \
	FOR_256_3(a, b, 2, 0) FOR_256_3(a, b, 2, 1) FOR_256_3(a, b, 2, 2) FOR_256_3(a, b, 2, 3) \
	FOR_256_3(a, b, 3, 0) FOR_256_3(a, b, 3, 1) FOR_256_3(a, b, 3, 2) FOR_256_3(a, b, 3, 3)
#define FOR_256 \
	FOR_256_2(0, 0) FOR_256_2(0, 1) FOR_256_2(0, 2) FOR_256_2(0, 3) \
	FOR_256_2(1, 0) FOR_256_2(1, 1) FOR_256_2(1, 2) FOR_256_2(1, 3) \
	FOR_256_2(2, 0) FOR_256_2(2, 1) FOR_256_2(2, 2) FOR_256_2(2, 3) \
	FOR_256_2(3, 0) FOR_256_2(3, 1) FOR_256_2(3, 2) FOR_256_2(3, 3) \

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

static void *resolveMissingFuncName(const char *dllName, const char *funcName) {
	DEBUG_LOG("Missing function: %s (%s)\n", dllName, funcName);
	assert(stubIndex < 0x100);
	assert(strlen(dllName) < 0x100);
	assert(strlen(funcName) < 0x100);
	strcpy(stubFuncNames[stubIndex], funcName);
	strcpy(stubDlls[stubIndex], dllName);
	return (void *)stubFuncs[stubIndex++];
}

static void *resolveMissingFuncOrdinal(const char *dllName, uint16_t ordinal) {
	char buf[16];
	sprintf(buf, "%d", ordinal);
	return resolveMissingFuncName(dllName, buf);
}

extern const wibo::Module lib_advapi32;
extern const wibo::Module lib_bcrypt;
extern const wibo::Module lib_crt;
extern const wibo::Module lib_kernel32;
extern const wibo::Module lib_lmgr;
extern const wibo::Module lib_mscoree;
extern const wibo::Module lib_msvcrt;
extern const wibo::Module lib_ntdll;
extern const wibo::Module lib_ole32;
extern const wibo::Module lib_user32;
extern const wibo::Module lib_vcruntime;
extern const wibo::Module lib_version;
const wibo::Module * wibo::modules[] = {
	&lib_advapi32,
	&lib_bcrypt,
	&lib_crt,
	&lib_kernel32,
	&lib_lmgr,
	&lib_mscoree,
	&lib_msvcrt,
	&lib_ntdll,
	&lib_ole32,
	&lib_user32,
	&lib_vcruntime,
	&lib_version,
	nullptr,
};

HMODULE wibo::loadModule(const char *dllName) {
	auto *result = new ModuleInfo;
	result->name = dllName;
	for (int i = 0; modules[i]; i++) {
		for (int j = 0; modules[i]->names[j]; j++) {
			if (strcasecmp(dllName, modules[i]->names[j]) == 0) {
				result->module = modules[i];
				return result;
			}
		}
	}
	return result;
}

void wibo::freeModule(HMODULE module) { delete static_cast<ModuleInfo *>(module); }

void *wibo::resolveFuncByName(HMODULE module, const char *funcName) {
	auto *info = static_cast<ModuleInfo *>(module);
	if (info && info->module && info->module->byName) {
		void *func = info->module->byName(funcName);
		if (func)
			return func;
	}
	return resolveMissingFuncName(info->name.c_str(), funcName);
}

void *wibo::resolveFuncByOrdinal(HMODULE module, uint16_t ordinal) {
	auto *info = static_cast<ModuleInfo *>(module);
	if (info && info->module && info->module->byOrdinal) {
		void *func = info->module->byOrdinal(ordinal);
		if (func)
			return func;
	}
	return resolveMissingFuncOrdinal(info->name.c_str(), ordinal);
}

wibo::Executable *wibo::executableFromModule(HMODULE module) {
	if (module == nullptr || module == wibo::mainModule->imageBuffer) {
		return wibo::mainModule;
	} else {
		auto info = static_cast<wibo::ModuleInfo *>(module);
		if (!info->executable) {
			DEBUG_LOG("wibo::executableFromModule: loading %s\n", info->name.c_str());
			info->executable = std::make_unique<wibo::Executable>();
			const auto path = files::pathFromWindows(info->name.c_str());
			FILE *f = fopen(path.c_str(), "rb");
			if (!f) {
				perror("wibo::executableFromModule");
				fclose(f);
				return nullptr;
			}
			if (!info->executable->loadPE(f, false)) {
				DEBUG_LOG("wibo::executableFromModule: failed to load %s\n", path.c_str());
				info->executable.reset();
				fclose(f);
				return nullptr;
			}
			fclose(f);
		}
		return info->executable.get();
	}
}

struct UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	uint16_t *Buffer;
};

// Run Time Library (RTL)
struct RTL_USER_PROCESS_PARAMETERS {
	char Reserved1[16];
	void *Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
};

// Windows Process Environment Block (PEB)
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

// Windows Thread Information Block (TIB)
struct TIB {
	/* 0x00 */ void *sehFrame;
	/* 0x04 */ void *stackBase;
	/* 0x08 */ void *stackLimit;
	/* 0x0C */ void *subSystemTib;
	/* 0x10 */ void *fiberData;
	/* 0x14 */ void *arbitraryDataSlot;
	/* 0x18 */ TIB *tib;
	/*      */ char pad[0x14];
	/* 0x30 */ PEB *peb;
	/*      */ char pad2[0x1000];
};

// Make this global to ease debugging
TIB tib;

int main(int argc, char **argv) {
	if (argc <= 1) {
		printf("Usage: ./wibo program.exe ...\n");
		return 1;
	}

	if (getenv("WIBO_DEBUG")) {
		wibo::debugEnabled = true;
	}

	if (getenv("WIBO_DEBUG_INDENT")) {
		wibo::debugIndent = std::stoul(getenv("WIBO_DEBUG_INDENT"));
	}


	files::init();

	// Create TIB
	memset(&tib, 0, sizeof(tib));
	tib.tib = &tib;
	tib.peb = (PEB*)calloc(sizeof(PEB), 1);
	tib.peb->ProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)calloc(sizeof(RTL_USER_PROCESS_PARAMETERS), 1);

	struct user_desc tibDesc;
	tibDesc.entry_number = 0;
	tibDesc.base_addr = (unsigned int) &tib;
	tibDesc.limit = 0x1000;
	tibDesc.seg_32bit = 1;
	tibDesc.contents = 0; // hopefully this is ok
	tibDesc.read_exec_only = 0;
	tibDesc.limit_in_pages = 0;
	tibDesc.seg_not_present = 0;
	tibDesc.useable = 1;
	if (syscall(SYS_modify_ldt, 1, &tibDesc, sizeof tibDesc) != 0) {
		perror("Failed to modify LDT\n");
		return 1;
	}

	// Build a command line
	std::string cmdLine;
	for (int i = 1; i < argc; i++) {
		std::string arg;
		if (i == 1) {
			arg = files::pathToWindows(std::filesystem::absolute(argv[1]));
		} else {
			cmdLine += ' ';
			arg = argv[i];
		}
		bool needQuotes = arg.find_first_of("\\\" \t\n") != std::string::npos;
		if (needQuotes)
			cmdLine += '"';
		int backslashes = 0;
		for (const char *p = arg.c_str(); ; p++) {
			char c = *p;
			if (c == '\\') {
				backslashes++;
				continue;
			}

			// Backslashes are doubled *before quotes*
			for (int j = 0; j < backslashes; j++) {
				cmdLine += '\\';
				if (c == '\0' || c == '"')
					cmdLine += '\\';
			}
			backslashes = 0;

			if (c == '\0')
				break;
			if (c == '\"')
				cmdLine += '\\';
			cmdLine += c;
		}
		if (needQuotes)
			cmdLine += '"';
	}
	cmdLine += '\0';

	wibo::commandLine = cmdLine.data();
	wibo::commandLineW = stringToWideString(wibo::commandLine);
	DEBUG_LOG("Command line: %s\n", wibo::commandLine);

	wibo::executableName = argv[0];
	wibo::argv = argv + 1;
	wibo::argc = argc - 1;

	wibo::Executable exec;
	wibo::mainModule = &exec;

	char* pe_path = argv[1];
	FILE *f = fopen(pe_path, "rb");
	if (!f) {
		std::string mesg = std::string("Failed to open file ") + pe_path;
		perror(mesg.c_str());
		return 1;
	}

	exec.loadPE(f, true);
	fclose(f);

	// 32-bit windows only reserves the lowest 2GB of memory for use by a process (https://www.tenouk.com/WinVirtualAddressSpace.html)
	// Linux, on the other hand, will happily allow nearly the entire 4GB address space to be used.
	// In order to prevent windows programs from being very confused as to why it's being handed
	// addresses in "invalid" memory, let's map the upper 2GB of memory to ensure libc can't allocate
	// anything there.
	std::ifstream procMap("/proc/self/maps");
	std::string procLine;
	unsigned int lastMapEnd = 0;

	const unsigned int FILL_MEMORY_ABOVE = 0x80000000; // 2GB

	while (getline(procMap, procLine)) {
		std::size_t idx = 0;
  		unsigned int mapStart = std::stoul(procLine, &idx, 16);
		unsigned int mapEnd = std::stoul(procLine.substr(idx + 1), nullptr, 16);

		// The empty space we want to map out is now between lastMapEnd and mapStart
		unsigned int holdingMapStart = lastMapEnd;
		unsigned int holdingMapEnd = mapStart;

		if ((holdingMapEnd - holdingMapStart) != 0 && holdingMapEnd > FILL_MEMORY_ABOVE) {
			holdingMapStart = std::max(holdingMapStart, FILL_MEMORY_ABOVE);

			void* holdingMap = mmap((void*) holdingMapStart, holdingMapEnd - holdingMapStart, PROT_READ, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);

			if (holdingMap == MAP_FAILED) {
				perror("Failed to create holding map");
				return 1;
			}
		}

		lastMapEnd = mapEnd;
	}

	procMap.close();

	uint16_t tibSegment = (tibDesc.entry_number << 3) | 7;
	// Invoke the damn thing
	asm(
		"movw %0, %%fs; call *%1"
		:
		: "r"(tibSegment), "r"(exec.entryPoint)
	);
	DEBUG_LOG("We came back\n");

	return 1;
}
