#pragma once

#include "types.h"

typedef void (_CC_STDCALL *PFLS_CALLBACK_FUNCTION)(void *);
constexpr DWORD FLS_OUT_OF_INDEXES = 0xFFFFFFFF;

namespace kernel32 {

DWORD WINAPI FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback);
BOOL WINAPI FlsFree(DWORD dwFlsIndex);
PVOID WINAPI FlsGetValue(DWORD dwFlsIndex);
BOOL WINAPI FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData);

} // namespace kernel32
