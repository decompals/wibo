#include "handles.h"
#include <atomic>
#include <cassert>
#include <cstdint>

namespace {

constexpr uint32_t kHandleAlignShift = 2;
// Max index that still yields HANDLE < 0x10000 with (index + 1) << 2
constexpr uint32_t kCompatMaxIndex = (0xFFFFu >> kHandleAlignShift) - 1;
// Delay reuse of small handles to avoid accidental stale aliasing
constexpr uint32_t kQuarantineLen = 64;

inline uint32_t indexOf(HANDLE h) noexcept {
	uint32_t v = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(h));
	if (v == 0 || (v & ((1U << kHandleAlignShift) - 1)) != 0) {
		return UINT32_MAX;
	}
	return (v >> kHandleAlignShift) - 1;
}

inline HANDLE makeHandle(uint32_t index) noexcept {
	uint32_t v = (index + 1) << kHandleAlignShift;
	return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(v));
}

inline bool isPseudo(HANDLE h) noexcept { return reinterpret_cast<int32_t>(h) < 0; }

} // namespace

Handles::~Handles() { clear(); }

void Handles::clear() {
	for (auto &entry : mSlots) {
		if (entry.obj) {
			detail::deref(entry.obj);
		}
	}
	mSlots.clear();
	mFreeBelow.clear();
	mFreeAbove.clear();
	nextIndex = 0;
}

HANDLE Handles::alloc(Pin<> obj, uint32_t grantedAccess, uint32_t flags) {
	std::unique_lock lk(m);

	// Attempt to, in order:
	// 1) use a fresh index in the compat range (0..kCompatMaxIndex)
	// 2) reuse a recently-freed index in the compat range
	// 3) reuse a recently-freed index above the compat range
	// 4) use a fresh index above the compat range
	uint32_t idx;
	if (nextIndex <= kCompatMaxIndex) {
		idx = nextIndex++;
		if (idx >= mSlots.size()) {
			mSlots.emplace_back();
		}
	} else if (!mFreeBelow.empty()) {
		idx = mFreeBelow.back();
		mFreeBelow.pop_back();
	} else if (!mFreeAbove.empty()) {
		idx = mFreeAbove.back();
		mFreeAbove.pop_back();
	} else {
		idx = static_cast<uint32_t>(mSlots.size());
		mSlots.emplace_back();
	}

	// Initialize entry
	auto &e = mSlots[idx];
	e.obj = obj.release(); // Transfer ownership
	e.meta.grantedAccess = grantedAccess;
	e.meta.flags = flags;
	e.meta.typeCache = e.obj->type;
	if (e.meta.generation == 0) {
		e.meta.generation = 1;
	}

	HANDLE h = makeHandle(idx);
	e.obj->handleCount.fetch_add(1, std::memory_order_relaxed);
	return h;
}

Pin<> Handles::get(HANDLE h, HandleMeta *metaOut) {
	if (h == nullptr || isPseudo(h)) {
		return {}; // pseudo-handles have no entries
	}

	std::shared_lock lk(m);
	const auto idx = indexOf(h);
	if (idx >= mSlots.size()) {
		return {};
	}

	const auto &e = mSlots[idx];
	if (!e.obj) {
		return {};
	}
	if (metaOut) {
		*metaOut = e.meta;
	}
	return Pin<>::acquire(e.obj);
}

bool Handles::release(HANDLE h) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(m);
	const auto idx = indexOf(h);
	if (idx >= mSlots.size()) {
		return false;
	}
	auto &e = mSlots[idx];
	if (!e.obj || e.meta.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return false;
	}

	ObjectBase *obj = e.obj;
	const auto generation = e.meta.generation + 1;
	e = {}; // Clear entry
	e.meta.generation = generation;
	uint32_t handleCount = obj->handleCount.fetch_sub(1, std::memory_order_relaxed) - 1;

	if (idx <= kCompatMaxIndex) {
		mQuarantine.push_back(idx);
		if (mQuarantine.size() > kQuarantineLen) {
			mFreeBelow.push_back(mQuarantine.front());
			mQuarantine.pop_front();
		}
	} else {
		mFreeAbove.push_back(idx);
	}
	lk.unlock();

	if (handleCount == 0 && mOnHandleZero) {
		mOnHandleZero(obj);
	}
	detail::deref(obj);
	return true;
}

bool Handles::setInformation(HANDLE h, uint32_t mask, uint32_t value) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(m);
	const auto idx = indexOf(h);
	if (idx >= mSlots.size()) {
		return false;
	}
	auto &e = mSlots[idx];
	if (!e.obj) {
		return false;
	}

	constexpr uint32_t kAllowedFlags = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
	mask &= kAllowedFlags;

	e.meta.flags = (e.meta.flags & ~mask) | (value & mask);
	return true;
}

bool Handles::getInformation(HANDLE h, uint32_t *outFlags) const {
	if (!outFlags) {
		return false;
	}
	if (isPseudo(h)) {
		*outFlags = 0;
		return true;
	}
	std::shared_lock lk(m);
	const auto idx = indexOf(h);
	if (idx >= mSlots.size()) {
		return false;
	}
	const auto &e = mSlots[idx];
	if (!e.obj) {
		return false;
	}
	*outFlags = e.meta.flags;
	return true;
}

bool Handles::duplicateTo(HANDLE src, Handles &dst, HANDLE &out, uint32_t desiredAccess, bool inherit,
						  uint32_t options) {
	HandleMeta meta{};
	Pin<> obj = get(src, &meta);
	if (!obj) {
		return false;
	}

	bool closeSource = (options & DUPLICATE_CLOSE_SOURCE) != 0;
	if (closeSource && (meta.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0) {
		// Cannot close source if it is protected
		return false;
	}

	uint32_t effAccess = (options & DUPLICATE_SAME_ACCESS) ? meta.grantedAccess : (desiredAccess & meta.grantedAccess);
	const uint32_t flags = (inherit ? HANDLE_FLAG_INHERIT : 0);

	// Reuse the same handle if duplicating with DUPLICATE_CLOSE_SOURCE within the same table and no changes
	if (&dst == this && closeSource && effAccess == meta.grantedAccess && flags == meta.flags) {
		out = src;
		return true;
	}

	out = dst.alloc(std::move(obj), effAccess, flags);

	if (closeSource) {
		release(src);
	}
	return true;
}

bool Namespace::insert(const std::u16string &name, ObjectBase *obj, bool permanent) {
	if (name.empty() || !obj) {
		return false;
	}
	std::unique_lock lk(m);
	// Namespace holds a weak ref
	const auto [_, inserted] = mTable.try_emplace(name, obj, permanent);
	return inserted;
}

void Namespace::remove(ObjectBase *obj) {
	std::unique_lock lk(m);
	for (auto it = mTable.begin(); it != mTable.end(); ++it) {
		if (it->second.obj == obj && !it->second.permanent) {
			mTable.erase(it);
			break;
		}
	}
}

Pin<> Namespace::get(const std::u16string &name) {
	if (name.empty()) {
		return {};
	}
	std::shared_lock lk(m);
	auto it = mTable.find(name);
	if (it == mTable.end()) {
		return {};
	}
	assert(it->second.obj);
	return Pin<>::acquire(it->second.obj);
}

void WaitableObject::registerWaiter(void *context, DWORD index, WaiterCallback cb) {
	if (!cb) {
		return;
	}
	std::lock_guard lk(waitersMutex);
	waiters.emplace_back(cb, context, index);
}

void WaitableObject::unregisterWaiter(void *context) {
	std::lock_guard lk(waitersMutex);
	waiters.erase(
		std::remove_if(waiters.begin(), waiters.end(), [context](const Waiter &w) { return w.context == context; }),
		waiters.end());
}

void WaitableObject::notifyWaiters(bool abandoned) {
	std::vector<Waiter> snapshot;
	{
		std::lock_guard lk(waitersMutex);
		snapshot = waiters;
	}
	for (const auto &w : snapshot) {
		if (w.callback) {
			w.callback(w.context, this, w.index, abandoned);
		}
	}
}

namespace wibo {

Namespace g_namespace;
Handles &handles() {
	static Handles table([](ObjectBase *obj) { g_namespace.remove(obj); });
	return table;
}

} // namespace wibo
