#pragma once

#include <cstdlib>

namespace handles {
	enum Type {
		TYPE_UNUSED,
		TYPE_FILE,
		TYPE_MAPPED,
		TYPE_PROCESS,
		TYPE_TOKEN,
		TYPE_MUTEX,
		TYPE_EVENT,
		TYPE_THREAD
	};

    struct Data {
        Type type = TYPE_UNUSED;
        void *ptr;
        size_t size;
    };

    Data dataFromHandle(void *handle, bool pop);
    void *allocDataHandle(Data data);
}
