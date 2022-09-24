#include "common.h"
#include "handles.h"
#include <utility>

namespace handles {
	static Data datas[0x10000];

    Data dataFromHandle(void *handle, bool pop) {
		uintptr_t index = (uintptr_t)handle;
		if (index > 0 && index < 0x10000) {
			Data ret = datas[index];
			if (pop)
				datas[index] = Data{};
			return ret;
		}
		if (pop)
			return Data{};
		printf("Invalid file handle %p\n", handle);
		assert(0);
	}

	void *allocDataHandle(Data data) {
		for (int i = 1; i < 0x10000; i++) {
			if (datas[i].type == TYPE_UNUSED) {
				datas[i] = data;
				return (void*)i;
			}
		}
		printf("Out of handles\n");
		assert(0);
	}
}
