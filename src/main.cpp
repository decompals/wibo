#include "common.h"
#include "context.h"
#include "files.h"
#include "modules.h"
#include "processes.h"
#include "strutil.h"

#include <asm/ldt.h>
#include <charconv>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <system_error>
#include <threads.h>
#include <unistd.h>
#include <vector>

thread_local uint32_t wibo::lastError = 0;
char **wibo::argv;
int wibo::argc;
std::filesystem::path wibo::guestExecutablePath;
std::string wibo::executableName;
std::string wibo::commandLine;
std::vector<uint16_t> wibo::commandLineW;
wibo::ModuleInfo *wibo::mainModule = nullptr;
bool wibo::debugEnabled = false;
unsigned int wibo::debugIndent = 0;
uint16_t wibo::tibSelector = 0;
int wibo::tibEntryNumber = -1;
PEB *wibo::processPeb = nullptr;

void wibo::debug_log(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (wibo::debugEnabled) {
		for (size_t i = 0; i < wibo::debugIndent; i++)
			fprintf(stderr, "\t");
		pthread_t threadId = pthread_self();
		fprintf(stderr, "[thread %lu] ", threadId);
		vfprintf(stderr, fmt, args);
		fflush(stderr);
	}

	va_end(args);
}

TIB *wibo::allocateTib() {
	auto *newTib = static_cast<TIB *>(std::calloc(1, sizeof(TIB)));
	if (!newTib) {
		return nullptr;
	}
	newTib->tib = newTib;
	newTib->peb = processPeb;
	return newTib;
}

void wibo::destroyTib(TIB *tibPtr) {
	if (!tibPtr) {
		return;
	}
	std::free(tibPtr);
}

void wibo::initializeTibStackInfo(TIB *tibPtr) {
	if (!tibPtr) {
		return;
	}
	pthread_attr_t attr;
	if (pthread_getattr_np(pthread_self(), &attr) != 0) {
		perror("Failed to get thread attributes");
		return;
	}
	void *stackAddr = nullptr;
	size_t stackSize = 0;
	if (pthread_attr_getstack(&attr, &stackAddr, &stackSize) == 0 && stackAddr && stackSize > 0) {
		tibPtr->stackLimit = stackAddr;
		tibPtr->stackBase = static_cast<char *>(stackAddr) + stackSize;
	} else {
		perror("Failed to get thread stack info");
	}
	DEBUG_LOG("initializeTibStackInfo: stackBase=%p stackLimit=%p\n", tibPtr->stackBase, tibPtr->stackLimit);
	pthread_attr_destroy(&attr);
}

bool wibo::installTibForCurrentThread(TIB *tibPtr) {
	if (!tibPtr) {
		return false;
	}
	struct user_desc desc;
	std::memset(&desc, 0, sizeof(desc));
	desc.entry_number = tibEntryNumber;
	desc.base_addr = reinterpret_cast<unsigned int>(tibPtr);
	desc.limit = static_cast<unsigned int>(sizeof(TIB) - 1);
	desc.seg_32bit = 1;
	desc.contents = 0;
	desc.read_exec_only = 0;
	desc.limit_in_pages = 0;
	desc.seg_not_present = 0;
	desc.useable = 1;
	if (syscall(SYS_set_thread_area, &desc) != 0) {
		perror("set_thread_area failed");
		return false;
	}
	if (tibSelector == 0) {
		tibEntryNumber = static_cast<int>(desc.entry_number);
		tibSelector = static_cast<uint16_t>((desc.entry_number << 3) | 3);
		DEBUG_LOG("set_thread_area: allocated selector=0x%x entry=%d base=%p\n", tibSelector, tibEntryNumber, tibPtr);
	} else {
		DEBUG_LOG("set_thread_area: reused selector=0x%x entry=%d base=%p\n", tibSelector, tibEntryNumber, tibPtr);
	}
	return true;
}

// Make this global to ease debugging
TIB tib;

const size_t MAPS_BUFFER_SIZE = 0x10000;

static void printHelp(const char *argv0) {
	std::filesystem::path exePath(argv0 ? argv0 : "wibo");
	std::string exeName = exePath.filename().string();
	fprintf(stdout, "Usage: %s [options] <program.exe> [arguments...]\n", exeName.c_str());
	fprintf(stdout, "       %s path [subcommand options] <path> [path...]\n", exeName.c_str());
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, "  --help\t\tShow this help message and exit\n");
	fprintf(stdout, "  -C, --chdir DIR\tChange working directory before launching the program\n");
	fprintf(stdout, "  -D, --debug\tEnable shim debug logging (same as WIBO_DEBUG=1)\n");
	fprintf(stdout, "  --cmdline STRING\tUse STRING as the exact guest command line\n");
	fprintf(stdout,
			"  --\t\tStop option parsing; following arguments are interpreted as the exact guest command line\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Subcommands:\n");
	fprintf(stdout, "  path\t\tConvert between host and Windows-style paths (see '%s path --help')\n", exeName.c_str());
}

static void printPathHelp(const char *argv0) {
	std::filesystem::path exePath(argv0 ? argv0 : "wibo");
	std::string exeName = exePath.filename().string();
	fprintf(stdout, "Usage: %s path (-u | --unix | -w | --windows) <path> [path...]\n", exeName.c_str());
	fprintf(stdout, "\n");
	fprintf(stdout, "Path Options:\n");
	fprintf(stdout, "  -u, --unix\tConvert Windows paths to host paths\n");
	fprintf(stdout, "  -w, --windows\tConvert host paths to Windows paths\n");
	fprintf(stdout, "  -h, --help\tShow this help message and exit\n");
}

static int handlePathCommand(int argc, char **argv, const char *argv0) {
	bool convertToUnix = false;
	bool convertToWindows = false;
	std::vector<const char *> inputs;

	for (int i = 0; i < argc; ++i) {
		const char *arg = argv[i];
		if (strcmp(arg, "-u") == 0 || strcmp(arg, "--unix") == 0) {
			convertToUnix = true;
			continue;
		}
		if (strcmp(arg, "-w") == 0 || strcmp(arg, "--windows") == 0) {
			convertToWindows = true;
			continue;
		}
		if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
			printPathHelp(argv0);
			return 0;
		}
		if (arg[0] == '-' && arg[1] != '\0') {
			fprintf(stderr, "Unknown option for 'path' subcommand: %s\n", arg);
			printPathHelp(argv0);
			return 1;
		}
		inputs.push_back(arg);
	}

	if (convertToUnix == convertToWindows) {
		fprintf(stderr, "Specify exactly one of --unix or --windows for the 'path' subcommand\n");
		printPathHelp(argv0);
		return 1;
	}
	if (inputs.empty()) {
		fprintf(stderr, "No path specified for conversion\n");
		printPathHelp(argv0);
		return 1;
	}

	for (const char *input : inputs) {
		if (convertToUnix) {
			auto hostPath = files::pathFromWindows(input).string();
			fprintf(stdout, "%s\n", hostPath.c_str());
		} else {
			std::filesystem::path hostInput(input);
			std::string windowsPath = files::pathToWindows(hostInput);
			fprintf(stdout, "%s\n", windowsPath.c_str());
		}
	}

	return 0;
}

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
static size_t readMaps(char *buffer) {
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
			void *holdingMap = mmap((void *)holdingMapStart, holdingMapEnd - holdingMapStart, PROT_READ | PROT_WRITE,
									MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);

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
	if (argc >= 2 && strcmp(argv[1], "path") == 0) {
		return handlePathCommand(argc - 2, argv + 2, argv[0]);
	}

	std::string chdirPath;
	bool optionDebug = false;
	bool parsingOptions = true;
	int programIndex = -1;
	std::string cmdLine;

	for (int i = 1; i < argc; ++i) {
		const char *arg = argv[i];
		if (parsingOptions) {
			if (strcmp(arg, "--") == 0) {
				parsingOptions = false;
				continue;
			}
			if (strncmp(arg, "--cmdline=", 10) == 0) {
				cmdLine = arg + 10;
				continue;
			}
			if (strcmp(arg, "--cmdline") == 0) {
				if (i + 1 >= argc) {
					fprintf(stderr, "Option %s requires a command line argument\n", arg);
					return 1;
				}
				cmdLine = argv[++i];
				continue;
			}
			if (strcmp(arg, "--help") == 0) {
				printHelp(argv[0]);
				return 0;
			}
			if (strcmp(arg, "-D") == 0 || strcmp(arg, "--debug") == 0) {
				optionDebug = true;
				continue;
			}
			if (strncmp(arg, "--chdir=", 8) == 0) {
				chdirPath = arg + 8;
				continue;
			}
			if (strcmp(arg, "-C") == 0 || strcmp(arg, "--chdir") == 0) {
				if (i + 1 >= argc) {
					fprintf(stderr, "Option %s requires a directory argument\n", arg);
					return 1;
				}
				chdirPath = argv[++i];
				continue;
			}
			if (strncmp(arg, "-C", 2) == 0 && arg[2] != '\0') {
				chdirPath = arg + 2;
				continue;
			}
			if (arg[0] == '-' && arg[1] != '\0') {
				fprintf(stderr, "Unknown option: %s\n", arg);
				fprintf(stderr, "\n");
				printHelp(argv[0]);
				return 1;
			}
		}

		programIndex = i;
		break;
	}

	if (programIndex == -1 && cmdLine.empty()) {
		printHelp(argv[0]);
		return argc <= 1 ? 0 : 1;
	}

	// Try to resolve our own executable path
	std::error_code ec;
	auto resolved = std::filesystem::read_symlink("/proc/self/exe", ec);
	std::string executablePath;
	if (!ec) {
		executablePath = resolved.string();
	} else {
		const char *selfArg = argv[0] ? argv[0] : "";
		auto absCandidate = std::filesystem::absolute(selfArg, ec);
		executablePath = ec ? std::string(selfArg) : absCandidate.string();
	}

	if (!chdirPath.empty()) {
		if (chdir(chdirPath.c_str()) != 0) {
			std::string message = std::string("Failed to chdir to ") + chdirPath;
			perror(message.c_str());
			return 1;
		}
	}

	if (optionDebug || getenv("WIBO_DEBUG")) {
		wibo::debugEnabled = true;
	}

	if (const char *debugIndentEnv = getenv("WIBO_DEBUG_INDENT")) {
		wibo::debugIndent = std::stoul(debugIndentEnv);
	}

	blockUpper2GB();
	files::init();
	wibo::processes().init();

	// Create TIB
	memset(&tib, 0, sizeof(tib));
	tib.tib = &tib;
	tib.peb = (PEB *)calloc(sizeof(PEB), 1);
	tib.peb->ProcessParameters = (RTL_USER_PROCESS_PARAMETERS *)calloc(sizeof(RTL_USER_PROCESS_PARAMETERS), 1);
	wibo::processPeb = tib.peb;
	wibo::initializeTibStackInfo(&tib);
	if (!wibo::installTibForCurrentThread(&tib)) {
		fprintf(stderr, "Failed to install TIB for main thread\n");
		return 1;
	}
	wibo::setThreadTibForHost(&tib);

	// Determine the guest program name
	auto guestArgs = wibo::splitCommandLine(cmdLine.c_str());
	std::string programName;
	if (programIndex != -1) {
		programName = argv[programIndex];
	} else if (!guestArgs.empty()) {
		programName = guestArgs[0];
	}
	if (programName.empty()) {
		fprintf(stderr, "No guest program specified\n");
		return 1;
	}

	// Resolve the guest program path
	std::filesystem::path resolvedGuestPath =
		wibo::resolveExecutable(programName, true).value_or(std::filesystem::path{});
	if (resolvedGuestPath.empty()) {
		fprintf(stderr, "Failed to resolve path to guest program %s\n", programName.c_str());
		return 1;
	}

	// Build guest arguments
	int argIndex = -1;
	bool skipProgramName = false;
	if (programIndex != -1 && argc > programIndex + 1) {
		argIndex = programIndex + 1;
		// With "test.exe -- test 1 2 3", treat everything after -- as the full command line
		if (strcmp(argv[argIndex], "--") == 0) {
			argIndex++;
			skipProgramName = true;
		}
	}
	if (guestArgs.empty() && !skipProgramName) {
		guestArgs.push_back(files::pathToWindows(resolvedGuestPath));
	}
	if (argIndex != -1) {
		for (int i = argIndex; i < argc; ++i) {
			guestArgs.emplace_back(argv[i]);
		}
	}

	// Build a command line
	if (cmdLine.empty()) {
		for (size_t i = 0; i < guestArgs.size(); ++i) {
			if (i != 0) {
				cmdLine += ' ';
			}
			const std::string &arg = guestArgs[i];
			bool needQuotes = arg.find_first_of("\" \t\n") != std::string::npos;
			if (needQuotes)
				cmdLine += '"';
			int backslashes = 0;
			for (const char *p = arg.c_str();; p++) {
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
	}
	if (cmdLine.empty() || cmdLine.back() != '\0') {
		cmdLine.push_back('\0');
	}

	wibo::commandLine = cmdLine;
	wibo::commandLineW = stringToWideString(wibo::commandLine.c_str());
	DEBUG_LOG("Command line: %s\n", wibo::commandLine.c_str());

	wibo::guestExecutablePath = resolvedGuestPath;
	wibo::executableName = executablePath;

	// Build argv/argc
	std::vector<char *> guestArgv;
	guestArgv.reserve(guestArgs.size() + 1);
	for (const auto &arg : guestArgs) {
		guestArgv.push_back(const_cast<char *>(arg.c_str()));
	}
	guestArgv.push_back(nullptr);
	wibo::argv = guestArgv.data();
	wibo::argc = static_cast<int>(guestArgv.size()) - 1;

	wibo::initializeModuleRegistry();

	FILE *f = fopen(resolvedGuestPath.c_str(), "rb");
	if (!f) {
		std::string mesg = std::string("Failed to open file ") + resolvedGuestPath.string();
		perror(mesg.c_str());
		return 1;
	}

	auto executable = std::make_unique<wibo::Executable>();
	if (!executable->loadPE(f, true)) {
		fclose(f);
		fprintf(stderr, "Failed to load PE image %s\n", resolvedGuestPath.c_str());
		return 1;
	}
	fclose(f);

	const auto entryPoint = executable->entryPoint;
	if (!entryPoint) {
		fprintf(stderr, "Executable %s has no entry point\n", resolvedGuestPath.c_str());
		return 1;
	}

	wibo::mainModule =
		wibo::registerProcessModule(std::move(executable), std::move(resolvedGuestPath), std::move(programName));
	if (!wibo::mainModule || !wibo::mainModule->executable) {
		fprintf(stderr, "Failed to register process module\n");
		return 1;
	}
	DEBUG_LOG("Registered main module %s at %p\n", wibo::mainModule->normalizedName.c_str(),
			  wibo::mainModule->executable->imageBase);

	if (!wibo::mainModule->executable->resolveImports()) {
		fprintf(stderr, "Failed to resolve imports for main module (DLL initialization failure?)\n");
		abort();
	}

	// Invoke the damn thing
	{
		GUEST_CONTEXT_GUARD(&tib);
		asm volatile("call *%0" : : "r"(entryPoint) : "memory");
	}
	DEBUG_LOG("We came back\n");
	wibo::shutdownModuleRegistry();

	return 1;
}
