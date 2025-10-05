#pragma once

#include "common.h"

namespace wibo {

class HostContextGuard {
  public:
	HostContextGuard();
	~HostContextGuard();
	HostContextGuard(const HostContextGuard &) = delete;
	HostContextGuard &operator=(const HostContextGuard &) = delete;

  private:
	uint16_t previousFs_;
	uint16_t previousGs_;
	bool restore_;
};

class GuestContextGuard {
  public:
	explicit GuestContextGuard(TIB *tib);
	~GuestContextGuard();
	GuestContextGuard(const GuestContextGuard &) = delete;
	GuestContextGuard &operator=(const GuestContextGuard &) = delete;

  private:
	uint16_t previousFs_;
	uint16_t previousGs_;
	bool applied_;
};

} // namespace wibo

#define HOST_CONTEXT_GUARD() wibo::HostContextGuard _wiboHostContextGuard
#define GUEST_CONTEXT_GUARD(tibPtr) wibo::GuestContextGuard _wiboGuestContextGuard(tibPtr)
