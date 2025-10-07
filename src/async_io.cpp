#include "async_io.h"

#include <memory>

namespace {

std::unique_ptr<wibo::AsyncIOBackend> g_backend;

class NoOpBackend : public wibo::AsyncIOBackend {
  public:
	bool init() override { return true; }
	void shutdown() override {}
	[[nodiscard]] bool running() const noexcept override { return true; }

	bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
				   const std::optional<off_t> &offset, bool isPipe) override {
		(void)file;
		(void)ov;
		(void)buffer;
		(void)length;
		(void)offset;
		(void)isPipe;
		return false; // Force synchronous fallback
	}
	bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
					const std::optional<off_t> &offset, bool isPipe) override {
		(void)file;
		(void)ov;
		(void)buffer;
		(void)length;
		(void)offset;
		(void)isPipe;
		return false; // Force synchronous fallback
	}
};

} // namespace

namespace wibo {

AsyncIOBackend &asyncIO() {
	if (!g_backend) {
#if WIBO_ENABLE_LIBURING
		g_backend = detail::createIoUringBackend();
#else
		g_backend = std::make_unique<NoOpBackend>();
#endif
	}
	if (!g_backend->init()) {
		DEBUG_LOG("AsyncIOBackend initialization failed; using no-op backend\n");
		g_backend = std::make_unique<NoOpBackend>();
	}
	return *g_backend;
}

} // namespace wibo
