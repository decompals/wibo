#pragma once

#include "types.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

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

namespace wibo {

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

TEB *allocateTib();
void destroyTib(TEB *tib);
void initializeTibStackInfo(TEB *tib);
bool installTibForCurrentThread(TEB *tib);
void setThreadTibForHost(TEB *tib);
TEB *getThreadTibForHost();

void debug_log(const char *fmt, ...);

} // namespace wibo
