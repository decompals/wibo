#pragma once

#include "handles.h"
#include "internal.h"
#include "minwinbase.h"

namespace kernel32::detail {

inline HANDLE normalizedOverlappedEventHandle(const OVERLAPPED *ov) {
	if (!ov || (ov->hEvent & 1U) != 0) {
		return NO_HANDLE;
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
