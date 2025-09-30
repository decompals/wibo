#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <sched.h>
#include <string>
#include <vector>

namespace processes {
    struct Process {
        pid_t pid;
        uint32_t exitCode;
        uint32_t forcedExitCode;
        bool terminationRequested;
    };

    void *allocProcessHandle(pid_t pid);
    Process* processFromHandle(void* hHandle, bool pop);

    std::optional<std::filesystem::path> resolveExecutable(const std::string &command, bool searchPath);
    int spawnWithCommandLine(const std::string &applicationName, const std::string &commandLine, pid_t *pidOut);
    int spawnWithArgv(const std::string &applicationName, const std::vector<std::string> &argv, pid_t *pidOut);
    std::vector<std::string> splitCommandLine(const char *commandLine);
}
