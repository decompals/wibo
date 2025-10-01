#include "common.h"
#include "handles.h"
#include <utility>

namespace handles {
	static Data datas[MAX_HANDLES];

    Data dataFromHandle(void *handle, bool pop) {
		uintptr_t index = (uintptr_t)handle;
		if (index > 0 && index < MAX_HANDLES) {
			Data ret = datas[index];
			if (pop)
				datas[index] = Data{};
			return ret;
		}
		return Data{};
	}

	void *allocDataHandle(Data data) {
		for (size_t i = 1; i < MAX_HANDLES; i++) {
			if (datas[i].type == TYPE_UNUSED) {
				datas[i] = data;
				return (void*)i;
			}
		}
		printf("Out of handles\n");
		assert(0);
	}
}
