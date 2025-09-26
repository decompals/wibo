#include "common.h"
#include "files.h"
#include "strutil.h"
#include <asm/ldt.h>
#include <charconv>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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

const size_t MAPS_BUFFER_SIZE = 0x10000;

/**
 * Read /proc/self/maps into a buffer.
 *
 * While reading /proc/self/maps, we need to be extremely careful not to allocate any memory,
 * as that could cause libc to modify memory mappings while we're attempting to fill them.
 * To accomplish this, we use Linux syscalls directly.
 *
 * @param buffer The buffer to read into.
 * @return The number of bytes read.
 */
static size_t readMaps(char* buffer) {
	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd == -1) {
		perror("Failed to open /proc/self/maps");
		exit(1);
	}

	char *cur = buffer;
	char *bufferEnd = buffer + MAPS_BUFFER_SIZE;
	while (cur < bufferEnd) {
		int ret = read(fd, cur, static_cast<size_t>(bufferEnd - cur));
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
			perror("Failed to read /proc/self/maps");
			exit(1);
		} else if (ret == 0) {
			break;
		}
		cur += ret;
	}
	close(fd);

	if (cur == bufferEnd) {
		fprintf(stderr, "Buffer too small while reading /proc/self/maps\n");
		exit(1);
	}
	*cur = '\0';
	return static_cast<size_t>(cur - buffer);
}

/**
 * Map the upper 2GB of memory to prevent libc from allocating there.
 *
 * This is necessary because 32-bit windows only reserves the lowest 2GB of memory for use by a process
 * (https://www.tenouk.com/WinVirtualAddressSpace.html). Linux, on the other hand, will happily allow
 * nearly the entire 4GB address space to be used. Some Windows programs rely on heap allocations to be
 * in the lower 2GB of memory, otherwise they misbehave or crash.
 *
 * Between reading /proc/self/maps and mmap-ing the upper 2GB, we must be extremely careful not to allocate
 * any memory, as that could cause libc to modify memory mappings while we're attempting to fill them.
 */
static void blockUpper2GB() {
	const unsigned int FILL_MEMORY_ABOVE = 0x80000000; // 2GB

	DEBUG_LOG("Blocking upper 2GB address space\n");

	// Buffer lives on the stack to avoid heap allocation
	char buffer[MAPS_BUFFER_SIZE];
	size_t len = readMaps(buffer);
	std::string_view procLine(buffer, len);
	unsigned int lastMapEnd = 0;
	while (true) {
		size_t newline = procLine.find('\n');
		if (newline == std::string::npos) {
			break;
		}

		unsigned int mapStart = 0;
		auto result = std::from_chars(procLine.data(), procLine.data() + procLine.size(), mapStart, 16);
		if (result.ec != std::errc()) {
			break;
		}
		unsigned int mapEnd = 0;
		result = std::from_chars(result.ptr + 1, procLine.data() + procLine.size(), mapEnd, 16);
		if (result.ec != std::errc()) {
			break;
		}

		// The empty space we want to map out is now between lastMapEnd and mapStart
		unsigned int holdingMapStart = lastMapEnd;
		unsigned int holdingMapEnd = mapStart;

		if ((holdingMapEnd - holdingMapStart) != 0 && holdingMapEnd > FILL_MEMORY_ABOVE) {
			holdingMapStart = std::max(holdingMapStart, FILL_MEMORY_ABOVE);

			// DEBUG_LOG("Mapping %08x-%08x\n", holdingMapStart, holdingMapEnd);
			void* holdingMap = mmap((void*) holdingMapStart, holdingMapEnd - holdingMapStart, PROT_READ | PROT_WRITE, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);

			if (holdingMap == MAP_FAILED) {
				perror("Failed to create holding map");
				exit(1);
			}
		}

		lastMapEnd = mapEnd;
		procLine = procLine.substr(newline + 1);
	}
}

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

	blockUpper2GB();
	files::init();

	// Create TIB
	memset(&tib, 0, sizeof(tib));
	tib.tib = &tib;
	tib.peb = (PEB*)calloc(sizeof(PEB), 1);
	tib.peb->ProcessParameters = (RTL_USER_PROCESS_PARAMETERS*)calloc(sizeof(RTL_USER_PROCESS_PARAMETERS), 1);

	struct user_desc tibDesc;
	memset(&tibDesc, 0, sizeof tibDesc);
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

	wibo::initializeModuleRegistry();

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

	uint16_t tibSegment = (tibDesc.entry_number << 3) | 7;
	// Invoke the damn thing
	asm(
		"movw %0, %%fs; call *%1"
		:
		: "r"(tibSegment), "r"(exec.entryPoint)
	);
	DEBUG_LOG("We came back\n");
	wibo::shutdownModuleRegistry();

	return 1;
}
