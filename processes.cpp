#include "processes.h"
#include "handles.h"
#include <cassert>
#include <cstdio>

namespace processes {
    void *allocProcessHandle(pid_t pid) {
		auto* process = new Process;
		process->pid = pid;
		process->exitCode = 0;

		return handles::allocDataHandle(handles::Data{handles::TYPE_PROCESS, (void*)process, 0});
	}

	Process* processFromHandle(void *handle, bool pop) {
		handles::Data data = handles::dataFromHandle(handle, pop);
		if (data.type == handles::TYPE_PROCESS) {
			return (Process*)data.ptr;
		} else {
			printf("Invalid file handle %p\n", handle);
			assert(0);
		}
	}
}