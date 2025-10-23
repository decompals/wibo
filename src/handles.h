#pragma once

#include "common.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <shared_mutex>
#include <utility>
#include <vector>

enum class ObjectType : uint16_t {
	File,
	Directory,
	Mapping,
	Process,
	Token,
	Mutex,
	Event,
	Semaphore,
	Thread,
	Heap,
	RegistryKey,
	NamedPipe,
};

enum ObjectFlags : uint16_t {
	Of_None = 0x0,
	Of_Waitable = 0x1,
};

struct ObjectBase {
	const ObjectType type;
	uint16_t flags = Of_None;
	std::atomic<uint32_t> pointerCount{0};
	std::atomic<uint32_t> handleCount{0};

	explicit ObjectBase(ObjectType t) noexcept : type(t) {}
	virtual ~ObjectBase() noexcept = default;
};

template <typename T>
concept ObjectBaseType = std::is_base_of_v<ObjectBase, T>;

struct WaitableObject : ObjectBase {
	bool signaled = false; // protected by m
	std::mutex m;
	std::condition_variable cv;

	using WaiterCallback = void (*)(void *, WaitableObject *, DWORD, bool);
	struct Waiter {
		WaiterCallback callback = nullptr;
		void *context = nullptr;
		DWORD index = 0;
	};
	std::mutex waitersMutex;
	std::vector<Waiter> waiters;

	explicit WaitableObject(ObjectType t) : ObjectBase(t) { flags |= Of_Waitable; }

	void registerWaiter(void *context, DWORD index, WaiterCallback cb);
	void unregisterWaiter(void *context);
	void notifyWaiters(bool abandoned);
};

namespace detail {

inline void ref(ObjectBase *o) noexcept { o->pointerCount.fetch_add(1, std::memory_order_relaxed); }
inline void deref(ObjectBase *o) noexcept {
	if (o->pointerCount.fetch_sub(1, std::memory_order_release) == 1) {
		std::atomic_thread_fence(std::memory_order_acquire);
		delete o;
	}
}

template <ObjectBaseType T> constexpr bool typeMatches(const ObjectBase *o) noexcept {
	if constexpr (requires { T::kType; }) {
		return o && o->type == T::kType;
	} else {
		static_assert(false, "No kType on U and no typeMatches<U> specialization provided");
	}
}
template <> constexpr bool typeMatches<WaitableObject>(const ObjectBase *o) noexcept {
	return o && (o->flags & Of_Waitable);
}

template <ObjectBaseType T> T *castTo(ObjectBase *o) noexcept {
	return typeMatches<T>(o) ? static_cast<T *>(o) : nullptr;
}

} // namespace detail

template <ObjectBaseType T = ObjectBase> class Pin {
  public:
	enum class Tag { Acquire, Adopt };

	Pin() = default;
	template <class U>
		requires std::is_convertible_v<U *, T *>
	explicit constexpr Pin(U *p, Tag t) noexcept : obj(static_cast<T *>(p)) {
		if (obj && t == Tag::Acquire) {
			detail::ref(obj);
		}
	}
	Pin(const Pin &) = delete;
	Pin(Pin &&other) noexcept : obj(other.release()) {}
	template <class U>
		requires std::is_base_of_v<T, U>
	Pin &operator=(Pin<U> &&other) noexcept {
		reset();
		obj = other.release();
		return *this;
	}
	template <class U>
		requires std::is_convertible_v<U *, T *>
	Pin(Pin<U> &&other) noexcept : obj(other.release()) {} // NOLINT(google-explicit-constructor)
	Pin &operator=(Pin &&other) noexcept {
		if (this != &other) {
			reset();
			obj = other.release();
		}
		return *this;
	}

	~Pin() noexcept { reset(); }

	static Pin acquire(T *o) noexcept { return Pin{o, Tag::Acquire}; }
	static constexpr Pin adopt(T *o) noexcept { return Pin{o, Tag::Adopt}; }

	[[nodiscard]] constexpr T *release() noexcept { return std::exchange(obj, nullptr); }
	void reset() noexcept {
		if (auto *obj = release()) {
			detail::deref(obj);
		}
	}

	constexpr T *operator->() const noexcept {
		assert(obj);
		return obj;
	}
	constexpr T &operator*() const noexcept {
		assert(obj);
		return *obj;
	}
	[[nodiscard]] constexpr T *get() const noexcept { return obj; }
	[[nodiscard]] Pin<T> clone() const noexcept { return Pin<T>::acquire(obj); }
	explicit constexpr operator bool() const noexcept { return obj != nullptr; }

	template <ObjectBaseType U> Pin<U> downcast() && noexcept {
		if constexpr (std::is_convertible_v<T *, U *>) {
			return std::move(*this);
		} else if (detail::typeMatches<U>(obj)) {
			return Pin<U>::adopt(static_cast<U *>(std::exchange(obj, nullptr)));
		}
		return Pin<U>{};
	}

  private:
	T *obj = nullptr;
};

template <ObjectBaseType T, class... Args>
	requires std::is_constructible_v<T, Args...>
inline Pin<T> make_pin(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>) {
	return Pin<T>::acquire(new T(std::forward<Args>(args)...));
}

constexpr DWORD HANDLE_FLAG_INHERIT = 0x1;
constexpr DWORD HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2;

constexpr DWORD DUPLICATE_CLOSE_SOURCE = 0x1;
constexpr DWORD DUPLICATE_SAME_ACCESS = 0x2;

struct HandleMeta {
	uint32_t grantedAccess;
	uint32_t flags;
	ObjectType typeCache;
	uint16_t generation;
};

// We have to stay under a HANDLE value of 0xFFFF for legacy applications,
// and handles values are aligned to 4.
constexpr DWORD MAX_HANDLES = 0x4000;

class Handles {
  public:
	using OnHandleZeroFn = void (*)(ObjectBase *);
	explicit Handles(OnHandleZeroFn cb) : mOnHandleZero(cb) {}
	~Handles();

	void clear();
	HANDLE alloc(Pin<> obj, uint32_t grantedAccess, uint32_t flags);
	bool release(HANDLE h);
	Pin<> get(HANDLE h, HandleMeta *metaOut = nullptr);
	template <ObjectBaseType T> Pin<T> getAs(HANDLE h, HandleMeta *metaOut = nullptr) {
		HandleMeta metaOutLocal{};
		if (!metaOut) {
			metaOut = &metaOutLocal;
		}
		auto obj = get(h, metaOut);
		if (!obj) {
			return {};
		}
		if constexpr (requires { T::kType; }) {
			if (metaOut->typeCache != T::kType) {
				return {};
			}
		}
		return std::move(obj).downcast<T>();
	}
	bool setInformation(HANDLE h, uint32_t mask, uint32_t value);
	bool getInformation(HANDLE h, uint32_t *outFlags) const;
	bool duplicateTo(HANDLE src, Handles &dst, HANDLE &out, uint32_t desiredAccess, bool inherit, uint32_t options);

  private:
	struct Entry {
		ObjectBase *obj;
		HandleMeta meta;
	};

	mutable std::shared_mutex m;
	std::vector<Entry> mSlots;
	OnHandleZeroFn mOnHandleZero = nullptr;
	std::vector<uint32_t> mFreeBelow;
	std::vector<uint32_t> mFreeAbove;
	std::deque<uint32_t> mQuarantine;
	uint32_t nextIndex = 0;
};

template <class F> using factory_ptr_t = std::remove_cvref_t<std::invoke_result_t<F &>>;
template <class F> using factory_obj_t = std::remove_pointer_t<factory_ptr_t<F>>;
template <class F>
concept ObjectFactoryFn =
	std::invocable<F &> && std::is_pointer_v<factory_ptr_t<F>> && ObjectBaseType<factory_obj_t<F>>;

class Namespace {
  public:
	bool insert(const std::u16string &name, ObjectBase *obj, bool permanent = false);
	void remove(ObjectBase *obj);
	Pin<> get(const std::u16string &name);

	template <ObjectBaseType T> Pin<T> getAs(const std::u16string &name) {
		if (auto pin = get(name)) {
			return std::move(pin).downcast<T>();
		}
		return {};
	}

	auto getOrCreate(const std::u16string &name, ObjectFactoryFn auto &&make)
		-> std::pair<Pin<factory_obj_t<decltype(make)>>, bool> {
		using T = factory_obj_t<decltype(make)>;
		if (name.empty()) {
			// No name: create unconditionally
			return {Pin<T>::acquire(std::invoke(make)), true};
		}
		if (auto existing = get(name)) {
			// Return even if downcast fails (don't use getAs<T>)
			return {std::move(existing).downcast<T>(), false};
		}
		auto newObj = Pin<T>::acquire(std::invoke(make));
		if (!newObj) {
			return {Pin<T>{}, false};
		}
		if (!insert(name, newObj.get())) {
			// Race: someone else inserted it first
			return {getAs<T>(name), false};
		}
		return {std::move(newObj), true};
	}

  private:
	struct Entry {
		ObjectBase *obj;
		bool permanent;
		Entry(ObjectBase *o, bool p) : obj(o), permanent(p) {}
	};

	mutable std::shared_mutex m;
	std::unordered_map<std::u16string, Entry> mTable;
};

namespace wibo {

extern Namespace g_namespace;
extern Handles &handles();

} // namespace wibo
