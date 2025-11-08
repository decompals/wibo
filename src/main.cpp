#include "common.h"
#include "entry.h"
#include "entry_trampolines.h"
#include "files.h"
#include "heap.h"
#include "modules.h"
#include "processes.h"
#include "strutil.h"
#include "tls.h"
#include "types.h"
#include "version_info.h"

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
#include <unistd.h>

#ifdef __x86_64__
#include "setup.h"
#endif

#ifdef __linux__
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <threads.h>
#endif

char **wibo::argv;
int wibo::argc;
std::filesystem::path wibo::guestExecutablePath;
std::string wibo::commandLine;
std::vector<uint16_t> wibo::commandLineW;
wibo::ModuleInfo *wibo::mainModule = nullptr;
bool wibo::debugEnabled = false;
unsigned int wibo::debugIndent = 0;
int wibo::tibEntryNumber = -1;
PEB *wibo::processPeb = nullptr;
thread_local TEB *currentThreadTeb = nullptr;

void wibo::debug_log(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (wibo::debugEnabled) {
		for (size_t i = 0; i < wibo::debugIndent; i++)
			fprintf(stderr, "\t");
		pthread_t threadId = pthread_self();
#ifdef __APPLE__
		fprintf(stderr, "[thread %p] ", threadId);
#else
		fprintf(stderr, "[thread %lu] ", threadId);
#endif
		vfprintf(stderr, fmt, args);
		fflush(stderr);
	}

	va_end(args);
}

TEB *wibo::allocateTib() {
	auto *newTib = static_cast<TEB *>(wibo::heap::guestCalloc(1, sizeof(TEB)));
	if (!newTib) {
		return nullptr;
	}
	tls::initializeTib(newTib);
	newTib->Tib.Self = toGuestPtr(newTib);
	newTib->Peb = toGuestPtr(processPeb);
	return newTib;
}

void wibo::destroyTib(TEB *tibPtr) {
	if (!tibPtr) {
		return;
	}
	tls::cleanupTib(tibPtr);
	std::free(tibPtr);
}

void wibo::initializeTibStackInfo(TEB *tibPtr) {
	if (!tibPtr) {
		return;
	}
	// Allocate a stack for the thread in the guest address space (below 2GB)
	void *guestLimit = nullptr;
	void *guestBase = nullptr;
	if (!wibo::heap::reserveGuestStack(1 * 1024 * 1024, &guestLimit, &guestBase)) {
		fprintf(stderr, "Failed to reserve guest stack\n");
		std::abort();
	}
	tibPtr->Tib.StackLimit = toGuestPtr(guestLimit);
	tibPtr->Tib.StackBase = toGuestPtr(guestBase);
	tibPtr->CurrentStackPointer = guestBase;
	DEBUG_LOG("initializeTibStackInfo: using guest stack base=%p limit=%p\n", tibPtr->Tib.StackBase,
			  tibPtr->Tib.StackLimit);
}

bool wibo::installTibForCurrentThread(TEB *tibPtr) {
	if (!tibPtr) {
		return false;
	}

	currentThreadTeb = tibPtr;
#ifdef __x86_64__
	tibEntryNumber = tebThreadSetup(tibEntryNumber, tibPtr);
	if (tibEntryNumber < 0 || tibPtr->CurrentFsSelector == 0) {
		perror("x86_64_thread_setup failed");
		return false;
	}
#else
	struct user_desc desc;
	std::memset(&desc, 0, sizeof(desc));
	desc.entry_number = tibEntryNumber;
	desc.base_addr = reinterpret_cast<uintptr_t>(tibPtr);
	desc.limit = static_cast<unsigned int>(sizeof(TEB) - 1);
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
	if (tibEntryNumber != static_cast<int>(desc.entry_number)) {
		tibEntryNumber = static_cast<int>(desc.entry_number);
		DEBUG_LOG("set_thread_area: allocated entry=%d base=%p\n", tibEntryNumber, tibPtr);
	} else {
		DEBUG_LOG("set_thread_area: reused entry=%d base=%p\n", tibEntryNumber, tibPtr);
	}

	tibPtr->CurrentFsSelector = static_cast<uint16_t>((desc.entry_number << 3) | 3);
	tibPtr->CurrentGsSelector = 0;
#endif
	return true;
}

static std::string getExeName(const char *argv0) {
	std::filesystem::path exePath(argv0 ? argv0 : "wibo");
	return exePath.filename().string();
}

static void printHelp(const char *argv0, bool error) {
	const auto exeName = getExeName(argv0);
	FILE *out = error ? stderr : stdout;
	if (error) {
		fprintf(out, "See '%s --help' for usage information.\n", exeName.c_str());
		return;
	}
	fprintf(out, "wibo %s\n\n", wibo::kVersionString);
	fprintf(out, "Usage:\n");
	fprintf(out, "  %s [options] <program.exe> [arguments...]\n", exeName.c_str());
	fprintf(out, "  %s path [subcommand options] <path> [path...]\n", exeName.c_str());
	fprintf(out, "\n");
	fprintf(out, "General Options:\n");
	fprintf(out, "  -h, --help            Show this help message and exit\n");
	fprintf(out, "  -V, --version         Show version information and exit\n");
	fprintf(out, "\n");
	fprintf(out, "Runtime Options:\n");
	fprintf(out, "  -C, --chdir DIR       Change working directory before launching the program\n");
	fprintf(out, "  -D, --debug           Enable debug logging (equivalent to WIBO_DEBUG=1)\n");
	fprintf(out, "      --cmdline STRING  Use STRING as the exact guest command line\n");
	fprintf(out, "                        (includes the program name, e.g. \"test.exe a b c\")\n");
	fprintf(out, "      --                Stop option parsing; following arguments are used\n");
	fprintf(out, "                        verbatim as the guest command line, including the\n");
	fprintf(out, "                        program name\n");
	fprintf(out, "\n");
	fprintf(out, "Subcommands:\n");
	fprintf(out, "  path                  Convert between host and Windows-style paths\n");
	fprintf(out, "                        (see '%s path --help' for details)\n", exeName.c_str());
	fprintf(out, "\n");
	fprintf(out, "Examples:\n");
	fprintf(out, "  # Normal usage\n");
	fprintf(out, "  %s path/to/test.exe a b c\n", exeName.c_str());
	fprintf(out, "  %s -C path/to test.exe a b c\n", exeName.c_str());
	fprintf(out, "\n");
	fprintf(out, "  # Advanced: full control over the guest command line\n");
	fprintf(out, "  %s path/to/test.exe -- test.exe a b c\n", exeName.c_str());
	fprintf(out, "  %s --cmdline 'test.exe a b c' path/to/test.exe\n", exeName.c_str());
	fprintf(out, "  %s -- test.exe a b c\n", exeName.c_str());
}

static void printPathHelp(const char *argv0, bool error) {
	const auto exeName = getExeName(argv0);
	FILE *out = error ? stderr : stdout;
	if (error) {
		fprintf(out, "See '%s path --help' for usage information.\n", exeName.c_str());
		return;
	}
	fprintf(out, "Usage:\n");
	fprintf(out, "  %s path [options] <path> [path...]\n", exeName.c_str());
	fprintf(out, "\n");
	fprintf(out, "Path Options (exactly one required):\n");
	fprintf(out, "  -u, --unix       Convert Windows paths to host (Unix-style) paths\n");
	fprintf(out, "  -w, --windows    Convert host (Unix-style) paths to Windows paths\n");
	fprintf(out, "\n");
	fprintf(out, "General Options:\n");
	fprintf(out, "  -h, --help       Show this help message and exit\n");
	fprintf(out, "\n");
	fprintf(out, "Examples:\n");
	fprintf(out, "  %s path -u 'Z:\\home\\user'\n", exeName.c_str());
	fprintf(out, "  %s path -w /home/user\n", exeName.c_str());
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
			printPathHelp(argv0, false);
			return 0;
		}
		if (arg[0] == '-' && arg[1] != '\0') {
			fprintf(stderr, "Error: unknown option '%s'.\n", arg);
			printPathHelp(argv0, true);
			return 1;
		}
		inputs.push_back(arg);
	}

	if (convertToUnix == convertToWindows) {
		if (!convertToUnix) {
			printPathHelp(argv0, false);
		} else {
			fprintf(stderr, "Error: cannot specify both --unix and --windows for path conversion.\n");
			printPathHelp(argv0, true);
		}
		return 1;
	}
	if (inputs.empty()) {
		fprintf(stderr, "Error: no paths specified for conversion.\n");
		printPathHelp(argv0, true);
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
			if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
				printHelp(argv[0], false);
				return 0;
			}
			if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
				fprintf(stdout, "wibo %s\n", wibo::kVersionString);
				return 0;
			}
			if (strncmp(arg, "--cmdline=", 10) == 0) {
				cmdLine = arg + 10;
				continue;
			}
			if (strcmp(arg, "--cmdline") == 0) {
				if (i + 1 >= argc) {
					fprintf(stderr, "Error: '%s' requires a command line argument.\n", arg);
					printHelp(argv[0], true);
					return 1;
				}
				cmdLine = argv[++i];
				continue;
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
					fprintf(stderr, "Error: '%s' requires a directory argument.\n", arg);
					printHelp(argv[0], true);
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
				fprintf(stderr, "Error: unknown option '%s'.\n", arg);
				printHelp(argv[0], true);
				return 1;
			}
		}

		programIndex = i;
		break;
	}

	if (programIndex == -1 && cmdLine.empty()) {
		if (argc == 1) {
			printHelp(argv[0], false);
			return 0;
		}
		fprintf(stderr, "Error: no program or command line specified.\n");
		printHelp(argv[0], true);
		return 1;
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

	files::init();

	// Create PEB
	PEB *peb = reinterpret_cast<PEB *>(wibo::heap::guestCalloc(1, sizeof(PEB)));
	peb->ProcessParameters = toGuestPtr(wibo::heap::guestCalloc(1, sizeof(RTL_USER_PROCESS_PARAMETERS)));

	// Create TIB
	TEB *tib = reinterpret_cast<TEB *>(wibo::heap::guestCalloc(1, sizeof(TEB)));
	wibo::tls::initializeTib(tib);
	tib->Tib.Self = toGuestPtr(tib);
	tib->Peb = toGuestPtr(peb);
	wibo::processPeb = peb;
	wibo::initializeTibStackInfo(tib);
	if (!wibo::installTibForCurrentThread(tib)) {
		fprintf(stderr, "Failed to install TIB for main thread\n");
		return 1;
	}

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

	const auto entryPoint = reinterpret_cast<EntryProc>(executable->entryPoint);
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
	if (!wibo::initializeModuleTls(*wibo::mainModule)) {
		fprintf(stderr, "Failed to initialize TLS for main module\n");
		return 1;
	}

	// Reset last error
	kernel32::setLastError(0);

	// Invoke the damn thing
	call_EntryProc(entryPoint);
	DEBUG_LOG("We came back\n");
	wibo::shutdownModuleRegistry();
	wibo::tls::cleanupTib(tib);

	return 1;
}
