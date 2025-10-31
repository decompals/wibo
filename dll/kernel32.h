#pragma once

#include "kernel32/debugapi.h"			// IWYU pragma: export
#include "kernel32/errhandlingapi.h"	// IWYU pragma: export
#include "kernel32/fibersapi.h"			// IWYU pragma: export
#include "kernel32/fileapi.h"			// IWYU pragma: export
#include "kernel32/handleapi.h"			// IWYU pragma: export
#include "kernel32/heapapi.h"			// IWYU pragma: export
#include "kernel32/interlockedapi.h"	// IWYU pragma: export
#include "kernel32/ioapiset.h"			// IWYU pragma: export
#include "kernel32/libloaderapi.h"		// IWYU pragma: export
#include "kernel32/memoryapi.h"			// IWYU pragma: export
#include "kernel32/namedpipeapi.h"		// IWYU pragma: export
#include "kernel32/processenv.h"		// IWYU pragma: export
#include "kernel32/processthreadsapi.h" // IWYU pragma: export
#include "kernel32/profileapi.h"		// IWYU pragma: export
#include "kernel32/stringapiset.h"		// IWYU pragma: export
#include "kernel32/synchapi.h"			// IWYU pragma: export
#include "kernel32/sysinfoapi.h"		// IWYU pragma: export
#include "kernel32/timezoneapi.h"		// IWYU pragma: export
#include "kernel32/winbase.h"			// IWYU pragma: export
#include "kernel32/wincon.h"			// IWYU pragma: export
#include "kernel32/winnls.h"			// IWYU pragma: export
#include "kernel32/winnt.h"				// IWYU pragma: export
#include "kernel32/wow64apiset.h"		// IWYU pragma: export

#ifndef WIBO_CODEGEN
#include "kernel32_trampolines.h" // IWYU pragma: export
#endif
