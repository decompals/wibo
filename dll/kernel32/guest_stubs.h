#pragma once

#include "types.h"

namespace wibo::guestStubs {

DWORD queryTickCount();
void *resolveByName(const char *name);

} // namespace wibo::guestStubs
