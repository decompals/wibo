#pragma once

#include "common.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <shared_mutex>
#include <utility>
#include <vector>

enum class ObjectType : uint16_t {
	File,
	Mapped,
	Process,
	Token,
	Mutex,
	Event,
	Semaphore,
	Thread,
	Heap,
	RegistryKey,
};

struct ObjectHeader {
	const ObjectType type;
	std::atomic<uint32_t> pointerCount{1};
	std::atomic<uint32_t> handleCount{0};

	explicit ObjectHeader(ObjectType t) : type(t) {}
	virtual ~ObjectHeader() = default;

	[[nodiscard]] virtual bool isWaitable() const { return false; }
	virtual void onDestroy() {}
};

namespace detail {

inline void ref(ObjectHeader *o) { o->pointerCount.fetch_add(1, std::memory_order_acq_rel); }
inline void deref(ObjectHeader *o) {
	if (o->pointerCount.fetch_sub(1, std::memory_order_acq_rel) == 1) {
		o->onDestroy();
		delete o;
	}
}

} // namespace detail

struct WaitableObject : ObjectHeader {
	std::atomic<bool> signaled{false};
	std::mutex m;
	std::condition_variable_any cv;

	using ObjectHeader::ObjectHeader;
	[[nodiscard]] bool isWaitable() const override { return true; }
};

template <class T> struct Pin {
	enum class Tag { Acquire, Adopt };

	T *obj = nullptr;

	Pin() = default;
	Pin(T *o, Tag t) : obj(o) {
		if (obj && t == Tag::Acquire) {
			detail::ref(obj);
		}
	}

	static Pin acquire(ObjectHeader *o) { return Pin{o, Tag::Acquire}; }
	static Pin adopt(ObjectHeader *o) { return Pin{o, Tag::Adopt}; }

	Pin(const Pin &) = delete;
	Pin &operator=(const Pin &) = delete;

	Pin(Pin &&other) noexcept : obj(std::exchange(other.obj, nullptr)) {}
	Pin &operator=(Pin &&other) noexcept {
		if (this != &other) {
			reset();
			obj = std::exchange(other.obj, nullptr);
		}
		return *this;
	}

	~Pin() { reset(); }

	ObjectHeader *release() { return std::exchange(obj, nullptr); }
	void reset() {
		if (obj) {
			detail::deref(obj);
			obj = nullptr;
		}
	}

	T *operator->() const { return obj; }
	T &operator*() const { return *obj; }
	explicit operator bool() const { return obj != nullptr; }

	template <class U> Pin<U> downcast() && {
		if (obj && obj->type == U::kType) {
			auto *u = static_cast<U *>(obj);
			obj = nullptr;
			return Pin<U>::adopt(u);
		}
		return Pin<U>{};
	}
};

using Handle = uint32_t;

constexpr DWORD HANDLE_FLAG_INHERIT = 0x1;
constexpr DWORD HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2;

constexpr DWORD DUPLICATE_CLOSE_SOURCE = 0x1;
constexpr DWORD DUPLICATE_SAME_ACCESS = 0x2;

struct HandleEntry {
	struct ObjectHeader *obj; // intrusive ref (pointerCount++)
	uint32_t grantedAccess;	  // effective access mask for this handle
	uint32_t flags;			  // inherit/protect/etc
	ObjectType typeCache;	  // cached ObjectType for fast getAs
	uint16_t generation;	  // must match handle’s generation
};

class HandleTable {
  public:
	Handle create(ObjectHeader *obj, uint32_t grantedAccess, uint32_t flags);
	bool close(Handle h);
	bool get(Handle h, HandleEntry &out, Pin<ObjectHeader> &pinOut);
	template <typename T> Pin<T> getAs(Handle h) {
		static_assert(std::is_base_of_v<ObjectHeader, T>, "T must derive from ObjectHeader");
		HandleEntry meta{};
		Pin<ObjectHeader> pin;
		if (!get(h, meta, pin)) {
			return {};
		}
		if constexpr (std::is_same_v<T, ObjectHeader>) {
			return std::move(pin);
		} else if (meta.typeCache != T::kType || pin->type != T::kType) {
			return {};
		} else {
			// Cast directly to T* and transfer ownership to Pin<T>
			return Pin<T>::adopt(static_cast<T *>(pin.release()));
		}
	}
	bool setInformation(Handle h, uint32_t mask, uint32_t value);
	bool getInformation(Handle h, uint32_t *outFlags) const;
	bool duplicateTo(Handle src, HandleTable &dst, Handle *out, uint32_t desiredAccess, bool inherit, uint32_t options);

  private:
	std::vector<HandleEntry> slots_;
	std::vector<uint32_t> freeList_;
	mutable std::shared_mutex mu_;
};

namespace handles {

constexpr size_t MAX_HANDLES = 0x10000;

enum Type {
	TYPE_UNUSED,
	TYPE_FILE,
	TYPE_MAPPED,
	TYPE_PROCESS,
	TYPE_TOKEN,
	TYPE_MUTEX,
	TYPE_EVENT,
	TYPE_SEMAPHORE,
	TYPE_THREAD,
	TYPE_HEAP,
	TYPE_REGISTRY_KEY
};

struct Data {
	Type type = TYPE_UNUSED;
	void *ptr;
	size_t size;
};

Data dataFromHandle(void *handle, bool pop);
void *allocDataHandle(Data data);
} // namespace handles
