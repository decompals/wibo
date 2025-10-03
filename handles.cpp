#include "handles.h"
#include "common.h"
#include <utility>

namespace {

constexpr uint32_t kIndexBits = 17;
constexpr uint32_t kIndexMask = (1u << kIndexBits) - 1; // 0x1FFFF
constexpr uint32_t kGenerationMask = (1u << 15) - 1;	// 0x7FFF
constexpr unsigned kGenerationShift = kIndexBits;		// 17

inline uint32_t indexOf(Handle h) { return h & kIndexMask; }
inline uint32_t generationOf(Handle h) { return (h >> kGenerationShift) & kGenerationMask; }
inline Handle makeHandle(uint32_t index, uint32_t gen) { return (gen << kGenerationShift) | index; }
inline bool isPseudo(Handle h) { return static_cast<int32_t>(h) < 0; }

} // namespace

Handle HandleTable::create(ObjectHeader *obj, uint32_t grantedAccess, uint32_t flags) {
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
	if (e.generation == 0) {
		e.generation = 1;
	}
	const uint16_t gen = e.generation;

	// Table owns one pointer ref for this entry
	detail::ref(obj);

	// Initialize entry
	e.obj = obj;
	e.grantedAccess = grantedAccess;
	e.flags = flags;
	e.typeCache = obj->type;

	const Handle h = makeHandle(idx, gen);
	obj->handleCount.fetch_add(1, std::memory_order_acq_rel);
	return h;
}

bool HandleTable::get(Handle h, HandleEntry &out, Pin<ObjectHeader> &pinOut) {
	if (isPseudo(h)) {
		return false; // pseudo-handles have no entries
	}

	std::shared_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	const auto &e = slots_[idx];
	if (e.generation != generationOf(h) || !e.obj) {
		return false;
	}

	detail::ref(e.obj);						  // pin under the lock
	pinOut = Pin<ObjectHeader>::adopt(e.obj); // dtor will deref
	out = e;
	return true;
}

bool HandleTable::close(Handle h) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	auto &e = slots_[idx];
	if (e.generation != generationOf(h) || !e.obj || e.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return false;
	}

	ObjectHeader *obj = e.obj;
	e.obj = nullptr; // tombstone
	auto newHandleCnt = obj->handleCount.fetch_sub(1, std::memory_order_acq_rel) - 1;

	// bump generation & recycle while still holding the lock
	e.generation = static_cast<uint16_t>((e.generation + 1) & kGenerationMask);
	freeList_.push_back(idx);
	lk.unlock();

	// if (newHandleCnt == 0) {
	// 	namespaceOnHandleCountZero(obj);
	// }
	detail::deref(obj);
	return true;
}

bool HandleTable::setInformation(Handle h, uint32_t mask, uint32_t value) {
	if (isPseudo(h)) {
		return true; // no-op, success
	}

	std::unique_lock lk(mu_);
	const auto idx = indexOf(h);
	if (idx >= slots_.size()) {
		return false;
	}
	auto &e = slots_[idx];
	if (e.generation != generationOf(h) || !e.obj) {
		return false;
	}

	constexpr uint32_t kAllowedFlags = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
	mask &= kAllowedFlags;

	e.flags = (e.flags & ~mask) | (value & mask);
	return true;
}

bool HandleTable::getInformation(Handle h, uint32_t *outFlags) const {
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
	if (e.generation != generationOf(h) || !e.obj) {
		return false;
	}
	*outFlags = e.flags;
	return true;
}

bool HandleTable::duplicateTo(Handle src, HandleTable &dst, Handle *out, uint32_t desiredAccess, bool inherit,
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

	HandleEntry e{};
	Pin<ObjectHeader> pin;
	if (!get(src, e, pin))
		return false;

	bool closeSource = (options & DUPLICATE_CLOSE_SOURCE) != 0;
	if (closeSource && (e.flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0) {
		// Cannot close source if it is protected
		return false;
	}

	uint32_t effAccess = (options & DUPLICATE_SAME_ACCESS) ? e.grantedAccess : (desiredAccess & e.grantedAccess);
	const uint32_t flags = (inherit ? HANDLE_FLAG_INHERIT : 0);
	*out = dst.create(pin.obj, effAccess, flags);

	if (closeSource) {
		close(src);
	}
	return true;
}

namespace handles {
static Data datas[MAX_HANDLES];

Data dataFromHandle(void *handle, bool pop) {
	uintptr_t index = (uintptr_t)handle;
	if (index > 0 && index < MAX_HANDLES) {
		Data ret = datas[index];
		if (pop)
			datas[index] = Data{};
		return ret;
	}
	return Data{};
}

void *allocDataHandle(Data data) {
	for (size_t i = 1; i < MAX_HANDLES; i++) {
		if (datas[i].type == TYPE_UNUSED) {
			datas[i] = data;
			return (void *)i;
		}
	}
	printf("Out of handles\n");
	assert(0);
}
} // namespace handles
