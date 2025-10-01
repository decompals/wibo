#pragma once

#include <cstdlib>

namespace handles {
	constexpr size_t MAX_HANDLES = 0x10000;

	enum Type {
		TYPE_UNUSED,
		TYPE_FILE,
		TYPE_MAPPED,
		TYPE_PROCESS,
		TYPE_TOKEN,
		TYPE_MUTEX,
		TYPE_EVENT,
		TYPE_SEMAPHORE,
		TYPE_THREAD,
		TYPE_HEAP,
		TYPE_REGISTRY_KEY
	};

    struct Data {
        Type type = TYPE_UNUSED;
        void *ptr;
        size_t size;
    };

    Data dataFromHandle(void *handle, bool pop);
    void *allocDataHandle(Data data);
}
