#include <stdlib.h>

namespace handles {
	enum Type {
        TYPE_UNUSED,
		TYPE_FILE,
		TYPE_MAPPED,
        TYPE_PROCESS
	};

    struct Data {
        Type type = TYPE_UNUSED;
        void *ptr;
        size_t size;
    };

    Data dataFromHandle(void *handle, bool pop);
    void *allocDataHandle(Data data);
}
