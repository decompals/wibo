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
    int spawnViaWibo(const std::filesystem::path &hostExecutable, const std::vector<std::string> &arguments, pid_t *pidOut);
    std::vector<std::string> splitCommandLine(const char *commandLine);
}
