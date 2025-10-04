#pragma once

#include "common.h"

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
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
};

struct ObjectBase {
	const ObjectType type;
	std::atomic<uint32_t> pointerCount{0};
	std::atomic<uint32_t> handleCount{0};

	explicit ObjectBase(ObjectType t) : type(t) {}
	virtual ~ObjectBase() = default;

	[[nodiscard]] virtual bool isWaitable() const { return false; }
};

namespace detail {

inline void ref(ObjectBase *o) { o->pointerCount.fetch_add(1, std::memory_order_acq_rel); }
inline void deref(ObjectBase *o) {
	if (o->pointerCount.fetch_sub(1, std::memory_order_acq_rel) == 1) {
		delete o;
	}
}

} // namespace detail

struct WaitableObject : ObjectBase {
	std::atomic<bool> signaled{false};
	std::mutex m;
	std::condition_variable_any cv;

	using ObjectBase::ObjectBase;
	[[nodiscard]] bool isWaitable() const override { return true; }
};

template <class T = ObjectBase> struct Pin {
	static_assert(std::is_base_of_v<ObjectBase, T> || std::is_same_v<ObjectBase, T>,
				  "Pin<T>: T must be ObjectBase or derive from it");

	T *obj = nullptr;

	Pin() = default;
	enum class Tag { Acquire, Adopt };
	template <class U, class = std::enable_if_t<std::is_convertible<U *, T *>::value>>
	explicit Pin(U *p, Tag t) : obj(static_cast<T *>(p)) {
		if (obj && t == Tag::Acquire) {
			detail::ref(obj);
		}
	}
	Pin(const Pin &) = delete;
	Pin(Pin &&other) noexcept : obj(std::exchange(other.obj, nullptr)) {}
	template <class U, class = std::enable_if_t<std::is_base_of<T, U>::value>> Pin &operator=(Pin<U> &&other) noexcept {
		reset();
		obj = std::exchange(other.obj, nullptr);
		return *this;
	}
	template <class U, class = std::enable_if_t<std::is_base_of<T, U>::value>>
	Pin(Pin<U> &&other) noexcept : obj(std::exchange(other.obj, nullptr)) {} // NOLINT(google-explicit-constructor)
	Pin &operator=(Pin &&other) noexcept {
		if (this != &other) {
			reset();
			obj = std::exchange(other.obj, nullptr);
		}
		return *this;
	}

	~Pin() { reset(); }

	static Pin acquire(T *o) { return Pin{o, Tag::Acquire}; }
	static Pin adopt(T *o) { return Pin{o, Tag::Adopt}; }

	[[nodiscard]] T *release() { return std::exchange(obj, nullptr); }
	void reset() {
		if (obj) {
			detail::deref(obj);
			obj = nullptr;
		}
	}

	T *operator->() const {
		assert(obj);
		return obj;
	}
	T &operator*() const {
		assert(obj);
		return *obj;
	}
	[[nodiscard]] T *get() const { return obj; }
	[[nodiscard]] Pin<T> clone() const { return Pin<T>::acquire(obj); }
	explicit operator bool() const { return obj != nullptr; }

	template <typename U> Pin<U> downcast() && {
		static_assert(std::is_base_of_v<ObjectBase, U>, "U must derive from ObjectBase");
		if constexpr (std::is_same_v<T, U>) {
			return std::move(*this);
		}
		if (obj && obj->type == U::kType) {
			auto *u = static_cast<U *>(obj);
			obj = nullptr;
			return Pin<U>::adopt(u);
		}
		return Pin<U>{};
	}
};

template <class T, class... Args>
Pin<T> make_pin(Args &&...args) noexcept(std::is_nothrow_constructible_v<T, Args...>) {
	T *p = new T(std::forward<Args>(args)...);
	return Pin<T>::acquire(p);
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

	HANDLE alloc(Pin<> obj, uint32_t grantedAccess, uint32_t flags);
	bool release(HANDLE h);
	Pin<> get(HANDLE h, HandleMeta *metaOut = nullptr);
	template <typename T> Pin<T> getAs(HANDLE h, HandleMeta *metaOut = nullptr) {
		static_assert(std::is_base_of_v<ObjectBase, T>, "T must derive from ObjectBase");
		HandleMeta metaOutLocal{};
		if (!metaOut) {
			metaOut = &metaOutLocal;
		}
		auto obj = get(h, metaOut);
		if (!obj) {
			return {};
		}
		if constexpr (std::is_same_v<T, ObjectBase>) {
			return std::move(obj);
		} else if (metaOut->typeCache != T::kType || obj->type != T::kType) {
			return {};
		} else {
			return Pin<T>::adopt(static_cast<T *>(obj.release()));
		}
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

class Namespace {
  public:
	bool insert(const std::u16string &name, ObjectBase *obj, bool permanent = false);
	void remove(ObjectBase *obj);
	Pin<> get(const std::u16string &name);

	template <typename T> Pin<T> getAs(const std::u16string &name) {
		if (auto pin = get(name)) {
			return std::move(pin).downcast<T>();
		}
		return {};
	}

	template <typename F, typename Ptr = std::invoke_result_t<F &>,
			  typename T = std::remove_pointer_t<std::decay_t<Ptr>>,
			  std::enable_if_t<std::is_pointer<std::decay_t<Ptr>>::value, int> = 0>
	std::pair<Pin<T>, bool> getOrCreate(const std::u16string &name, F &&make) {
		if (name.empty()) {
			// No name: create unconditionally
			T *raw = std::invoke(std::forward<F>(make));
			return {Pin<T>::acquire(raw), true};
		}
		if (auto existing = get(name)) {
			// Return even if downcast fails (don't use getAs<T>)
			return {std::move(existing).downcast<T>(), false};
		}
		T *raw = std::invoke(std::forward<F>(make));
		Pin<T> newObj = Pin<T>::acquire(raw);
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
