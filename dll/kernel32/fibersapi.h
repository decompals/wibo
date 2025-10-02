#pragma once

#include "common.h"

using PFLS_CALLBACK_FUNCTION = void (*)(void *);
constexpr DWORD FLS_OUT_OF_INDEXES = 0xFFFFFFFF;

namespace kernel32 {

DWORD WIN_FUNC FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback);
BOOL WIN_FUNC FlsFree(DWORD dwFlsIndex);
PVOID WIN_FUNC FlsGetValue(DWORD dwFlsIndex);
BOOL WIN_FUNC FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData);

} // namespace kernel32
