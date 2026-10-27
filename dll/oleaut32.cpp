#include "oleaut32.h"

#include "common.h"
#include "context.h"
#include "heap.h"
#include "modules.h"

#include <cstring>

namespace {

// A BSTR points at NUL-terminated data preceded by its length in bytes.
constexpr size_t kPrefixBytes = sizeof(uint32_t);

void *blockFromBstr(BSTR bstr) { return reinterpret_cast<uint8_t *>(bstr) - kPrefixBytes; }

BSTR allocateBstr(const OLECHAR *source, UINT chars) {
	size_t bytes = static_cast<size_t>(chars) * sizeof(OLECHAR);
	auto *block = static_cast<uint8_t *>(wibo::heap::guestMalloc(kPrefixBytes + bytes + sizeof(OLECHAR)));
	if (!block) {
		return nullptr;
	}
	*reinterpret_cast<uint32_t *>(block) = static_cast<uint32_t>(bytes);
	auto *data = reinterpret_cast<OLECHAR *>(block + kPrefixBytes);
	if (source) {
		std::memcpy(data, source, bytes);
	} else {
		std::memset(data, 0, bytes);
	}
	data[chars] = 0;
	return data;
}

} // namespace

namespace oleaut32 {

BSTR WINAPI SysAllocStringLen(const OLECHAR *strIn, UINT ui) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SysAllocStringLen(%p, %u)\n", strIn, ui);
	return allocateBstr(strIn, ui);
}

void WINAPI SysFreeString(BSTR bstrString) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SysFreeString(%p)\n", bstrString);
	if (!bstrString) {
		return;
	}
	wibo::heap::guestFree(blockFromBstr(bstrString));
}

} // namespace oleaut32

#include "oleaut32_trampolines.h"

extern const wibo::ModuleStub lib_oleaut32 = {
	(const char *[]){
		"oleaut32",
		nullptr,
	},
	oleaut32ThunkByName,
	nullptr,
};
