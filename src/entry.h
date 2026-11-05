#pragma once

#include "types.h"

typedef VOID(_CC_CDECL *EntryProc)();
typedef BOOL(_CC_STDCALL *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef VOID(_CC_STDCALL *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

namespace entry {

void CDECL stubBase(SIZE_T index);
GUEST_PTR WINAPI beginDispatch(GUEST_PTR frame);
GUEST_PTR WINAPI continueDispatch(GUEST_PTR frame, LONG disposition);
GUEST_PTR WINAPI beginUnwind(GUEST_PTR frame, GUEST_PTR targetFrame, GUEST_PTR exceptionRecord);
GUEST_PTR WINAPI continueUnwind(GUEST_PTR frame, LONG disposition);
LONG CDECL dispatchProtector(GUEST_PTR exceptionRecord, GUEST_PTR establisherFrame, GUEST_PTR contextRecord,
							 GUEST_PTR dispatcherContext);
LONG CDECL unwindProtector(GUEST_PTR exceptionRecord, GUEST_PTR establisherFrame, GUEST_PTR contextRecord,
						   GUEST_PTR dispatcherContext);

} // namespace entry
