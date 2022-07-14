#include "common.h"
#include "files.h"
#include <asm/ldt.h>
#include <filesystem>
#include <errno.h>
#include <memory>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdarg.h>

uint32_t wibo::lastError = 0;
char *wibo::commandLine;
wibo::Executable *wibo::mainModule = 0;
bool wibo::debugEnabled = false;

void wibo::debug_log(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (wibo::debugEnabled)
		vprintf(fmt, args);
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

static void *resolveMissingFunc(const char *dllName, const char *funcName) {
	DEBUG_LOG("Missing function: %s (%s)\n", dllName, funcName);
	assert(stubIndex < 0x100);
	assert(strlen(dllName) < 0x100);
	assert(strlen(funcName) < 0x100);
	strcpy(stubFuncNames[stubIndex], funcName);
	strcpy(stubDlls[stubIndex], dllName);
	return (void *) stubFuncs[stubIndex++];
}

void *wibo::resolveFuncByName(const char *dllName, const char *funcName) {
	void *func = nullptr;
	if (strcasecmp(dllName, "KERNEL32.dll") == 0) {
		func = wibo::resolveKernel32(funcName);
	} else if (strcasecmp(dllName, "USER32.dll") == 0) {
		func = wibo::resolveUser32(funcName);
	} else if (strcasecmp(dllName, "ADVAPI32.dll") == 0) {
		func = wibo::resolveAdvApi32(funcName);
	} else if (strcasecmp(dllName, "VERSION.dll") == 0) {
		func = wibo::resolveVersion(funcName);
	} else if (strcasecmp(dllName, "OLE32.dll") == 0) {
		func = wibo::resolveOle32(funcName);
	}

	if (func)
		return func;
	return resolveMissingFunc(dllName, funcName);
}

void *wibo::resolveFuncByOrdinal(const char *dllName, uint16_t ordinal) {
	void *func;
	if (strcmp(dllName, "LMGR11.dll") == 0 ||
			strcmp(dllName, "LMGR326B.dll") == 0 ||
			strcmp(dllName, "LMGR8C.dll") == 0) {
		func = wibo::resolveLmgr(ordinal);
	}

	if (func)
		return func;
	char buf[16];
	sprintf(buf, "%d", ordinal);
	return resolveMissingFunc(dllName, buf);
}

// Windows Thread Information Block
struct TIB {
	void *sehFrame;
	void *stackBase;
	void *stackLimit;
	void *subSystemTib;
	void *fiberData;
	void *arbitraryDataSlot;
	TIB *tib;
};

int main(int argc, char **argv) {
	if (argc <= 1) {
		printf("Usage: ./wibo program.exe ...\n");
		return 1;
	}

	if (getenv("WIBO_DEBUG")) {
		wibo::debugEnabled = true;
	}

	files::init();

	// Create TIB
	TIB tib;
	tib.tib = &tib;

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
		if (i != 1) cmdLine += ' ';
		std::string arg = argv[i];
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
	DEBUG_LOG("Command line: %s\n", wibo::commandLine);

	wibo::Executable exec;
	wibo::mainModule = &exec;

	char* pe_path = argv[1];
	FILE *f = fopen(pe_path, "rb");
	if (!f) {
		std::string mesg = std::string("Failed to open file ") + pe_path;
		perror(mesg.c_str());
		return 1;
	}

	exec.loadPE(f);
	fclose(f);

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
