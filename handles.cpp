#include "handles.h"

namespace {

constexpr uint32_t kIndexBits = 17;
constexpr uint32_t kIndexMask = (1u << kIndexBits) - 1; // 0x1FFFF
constexpr uint32_t kGenerationMask = (1u << 15) - 1;	// 0x7FFF
constexpr unsigned kGenerationShift = kIndexBits;		// 17

inline uint32_t indexOf(HANDLE h) { return reinterpret_cast<uint32_t>(h) & kIndexMask; }
inline uint32_t generationOf(HANDLE h) { return (reinterpret_cast<uint32_t>(h) >> kGenerationShift) & kGenerationMask; }
inline HANDLE makeHandle(uint32_t index, uint32_t gen) {
	return reinterpret_cast<HANDLE>((gen << kGenerationShift) | index);
}
inline bool isPseudo(HANDLE h) { return reinterpret_cast<int32_t>(h) < 0; }

} // namespace

HANDLE HandleTable::create(ObjectHeader *obj, uint32_t grantedAccess, uint32_t flags) {
	std::unique_lock lk(mu_);

	uint32_t idx;
	if (!freeList_.empty()) {
		idx = freeList_.back();
		freeList_.pop_back();
	} else {
		idx = static_cast<uint32_t>(slots_.size());
		slots_.push_back(HandleEntry{});
	}

	auto &e = slots_[idx];

	// Initialize generation if needed
	if (e.meta.generation == 0) {
		e.meta.generation = 1;
	}
	const uint16_t gen = e.meta.generation;

	// Table owns one pointer ref for this entry
	detail::ref(obj);

	// Initialize entry
	e.obj = obj;
	e.meta.grantedAccess = grantedAccess;
	e.meta.flags = flags;
	e.meta.typeCache = obj->type;

	HANDLE h = makeHandle(idx, gen);
	obj->handleCount.fetch_add(1, std::memory_order_acq_rel);
	return h;
}

bool HandleTable::get(HANDLE h, Pin<ObjectHeader> &pinOut, HandleMeta *metaOut) {
	if (isPseudo(h)) {
		return false; // pseudo-handles have no entries
	}

	std::shared_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	const auto &e = slots_[idx];
	if (e.meta.generation != generationOf(h) || !e.obj) {
		return false;
	}

	detail::ref(e.obj);						  // pin under the lock
	pinOut = Pin<ObjectHeader>::adopt(e.obj); // dtor will deref
	if (metaOut) {
		*metaOut = e.meta;
	}
	return true;
}

bool HandleTable::close(HANDLE h) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	auto &e = slots_[idx];
	if (e.meta.generation != generationOf(h) || !e.obj || e.meta.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return false;
	}

	ObjectHeader *obj = e.obj;
	e.obj = nullptr; // tombstone
	/*auto newHandleCnt =*/ obj->handleCount.fetch_sub(1, std::memory_order_acq_rel) /* - 1*/;

	// bump generation & recycle while still holding the lock
	e.meta.generation = static_cast<uint16_t>((e.meta.generation + 1) & kGenerationMask);
	freeList_.push_back(idx);
	lk.unlock();

	// if (newHandleCnt == 0) {
	// 	namespaceOnHandleCountZero(obj);
	// }
	detail::deref(obj);
	return true;
}

bool HandleTable::setInformation(HANDLE h, uint32_t mask, uint32_t value) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	auto &e = slots_[idx];
	if (e.meta.generation != generationOf(h) || !e.obj) {
		return false;
	}

	constexpr uint32_t kAllowedFlags = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
	mask &= kAllowedFlags;

	e.meta.flags = (e.meta.flags & ~mask) | (value & mask);
	return true;
}

bool HandleTable::getInformation(HANDLE h, uint32_t *outFlags) const {
	if (!outFlags) {
		return false;
	}
	if (isPseudo(h)) {
		*outFlags = 0;
		return true;
	}
	std::shared_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	const auto &e = slots_[idx];
	if (e.meta.generation != generationOf(h) || !e.obj) {
		return false;
	}
	*outFlags = e.meta.flags;
	return true;
}

bool HandleTable::duplicateTo(HANDLE src, HandleTable &dst, HANDLE *out, uint32_t desiredAccess, bool inherit,
							  uint32_t options) {
	if (!out)
		return false;

	// Pseudo-handles: resolve to a Borrow of the live object
	// if (isPseudo(src)) {
	// 	Pin pin = resolvePseudoBorrow(src);
	// 	if (!pin)
	// 		return false;
	// 	const uint32_t granted = desiredAccess; // or compute from type; pseudo has full rights to self
	// 	*out = dst.create(pin.obj, granted, inherit ? HANDLE_FLAG_INHERIT : 0);
	// 	return true;
	// }

	HandleMeta meta{};
	Pin<ObjectHeader> pin;
	if (!get(src, pin, &meta)) {
		return false;
	}

	bool closeSource = (options & DUPLICATE_CLOSE_SOURCE) != 0;
	if (closeSource && (meta.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0) {
		// Cannot close source if it is protected
		return false;
	}

	uint32_t effAccess = (options & DUPLICATE_SAME_ACCESS) ? meta.grantedAccess : (desiredAccess & meta.grantedAccess);
	const uint32_t flags = (inherit ? HANDLE_FLAG_INHERIT : 0);
	*out = dst.create(pin.obj, effAccess, flags);

	if (closeSource) {
		close(src);
	}
	return true;
}
