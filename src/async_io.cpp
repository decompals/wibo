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

using BackendFactory = auto (*)() -> std::unique_ptr<AsyncIOBackend>;

struct BackendEntry {
	const char *name;
	BackendFactory factory;
};

static constexpr BackendEntry kBackends[] = {
#if WIBO_ENABLE_LIBURING
	{"io_uring", detail::createIoUringBackend},
#endif
#ifdef __linux__
	{"epoll", detail::createEpollBackend},
#endif
};

AsyncIOBackend &asyncIO() {
	if (!g_backend) {
		for (const auto &entry : kBackends) {
			DEBUG_LOG("AsyncIO: initializing %s backend\n", entry.name);
			auto backend = entry.factory();
			if (backend && backend->init()) {
				g_backend = std::move(backend);
				break;
			} else {
				DEBUG_LOG("AsyncIO: %s backend unavailable\n", entry.name);
				if (backend) {
					backend->shutdown();
				}
			}
		}
	}

	if (!g_backend) {
		DEBUG_LOG("AsyncIO: no backend available; using no-op backend\n");
		g_backend = std::make_unique<NoOpBackend>();
		g_backend->init();
	}

	return *g_backend;
}

} // namespace wibo
