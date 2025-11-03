#pragma once

#include "types.h"

typedef VOID(_CC_CDECL *EntryProc)();
typedef BOOL(_CC_STDCALL *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef VOID(_CC_STDCALL *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

namespace entry {

void CDECL stubBase(SIZE_T index);

} // namespace entry
