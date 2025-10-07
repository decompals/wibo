#pragma once

#include "context.h"
#include "handles.h"
#include "internal.h"
#include "minwinbase.h"

#include <cstdint>

namespace kernel32::detail {

inline bool shouldSignalOverlappedEvent(const OVERLAPPED *ov) {
	if (!ov) {
		return false;
	}
	auto raw = reinterpret_cast<uintptr_t>(ov->hEvent);
	return (raw & 1U) == 0 && raw != 0;
}

inline HANDLE normalizedOverlappedEventHandle(const OVERLAPPED *ov) {
	if (!ov) {
		return nullptr;
	}
	auto raw = reinterpret_cast<uintptr_t>(ov->hEvent);
	raw &= ~static_cast<uintptr_t>(1);
	return reinterpret_cast<HANDLE>(raw);
}

inline void signalOverlappedEvent(OVERLAPPED *ov) {
	if (!shouldSignalOverlappedEvent(ov)) {
		return;
	}
	HANDLE handle = normalizedOverlappedEventHandle(ov);
	if (handle) {
		if (auto ev = wibo::handles().getAs<EventObject>(handle)) {
			ev->set();
		}
	}
}

inline void resetOverlappedEvent(OVERLAPPED *ov) {
	if (!ov) {
		return;
	}
	HANDLE handle = normalizedOverlappedEventHandle(ov);
	if (handle) {
		if (auto ev = wibo::handles().getAs<EventObject>(handle)) {
			ev->reset();
		}
	}
}

} // namespace kernel32::detail
