#pragma once

#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "minwinbase.h"

#include <cstdint>

namespace kernel32::detail {

inline HANDLE normalizedOverlappedEventHandle(const OVERLAPPED *ov) {
	if (!ov || (reinterpret_cast<uintptr_t>(ov->hEvent) & 1U) != 0) {
		return nullptr;
	}
	return ov->hEvent;
}

inline void signalOverlappedEvent(FileObject *file, OVERLAPPED *ov, NTSTATUS status, size_t bytesTransferred) {
	if (ov) {
		ov->Internal = status;
		ov->InternalHigh = static_cast<ULONG_PTR>(bytesTransferred);
	}
	if (HANDLE handle = normalizedOverlappedEventHandle(ov)) {
		if (auto ev = wibo::handles().getAs<EventObject>(handle)) {
			ev->set();
		}
	}
	if (file) {
		file->overlappedCv.notify_all();
	}
}

inline void resetOverlappedEvent(OVERLAPPED *ov) {
	if (HANDLE handle = normalizedOverlappedEventHandle(ov)) {
		if (auto ev = wibo::handles().getAs<EventObject>(handle)) {
			ev->reset();
		}
	}
}

} // namespace kernel32::detail
