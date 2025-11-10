#pragma once

#include "kernel32/internal.h"
#include "kernel32/minwinbase.h"

#include <optional>

namespace wibo {

class AsyncIOBackend {
  public:
	virtual ~AsyncIOBackend() = default;
	virtual bool init() = 0;
	virtual void shutdown() = 0;
	[[nodiscard]] virtual bool running() const noexcept = 0;
	virtual bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
						   const std::optional<off_t> &offset, bool isPipe) = 0;
	virtual bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
							const std::optional<off_t> &offset, bool isPipe) = 0;
};

namespace detail {

#if WIBO_ENABLE_LIBURING
std::unique_ptr<AsyncIOBackend> createIoUringBackend();
#endif
#ifdef __linux__
std::unique_ptr<AsyncIOBackend> createEpollBackend();
#endif
#ifdef __APPLE__
std::unique_ptr<AsyncIOBackend> createKqueueBackend();
#endif

} // namespace detail

AsyncIOBackend &asyncIO();

} // namespace wibo
