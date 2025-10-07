#pragma once

#include "kernel32/internal.h"
#include "kernel32/minwinbase.h"

#include <optional>

namespace async_io {

bool initialize();
void shutdown();
bool running();

bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
			   const std::optional<off64_t> &offset, bool isPipe);
bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
				const std::optional<off64_t> &offset, bool isPipe);

} // namespace async_io
