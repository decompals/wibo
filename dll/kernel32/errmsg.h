#pragma once

#include "types.h"

namespace kernel32 {

[[nodiscard]] const char *lookupSystemMessage(DWORD code);

}
