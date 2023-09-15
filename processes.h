#include <sched.h>

namespace processes {
    struct Process {
        pid_t pid;
        unsigned int exitCode;
    };

    void *allocProcessHandle(pid_t pid);
    Process* processFromHandle(void* hHandle, bool pop);
}