#pragma once

#include <cstdint>
#include <sched.h>

namespace processes {
    struct Process {
        pid_t pid;
        uint32_t exitCode;
    };

    void *allocProcessHandle(pid_t pid);
    Process* processFromHandle(void* hHandle, bool pop);
}
