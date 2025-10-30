#pragma once

#include "types.h"

namespace kernel32 {

BOOL WINAPI Wow64DisableWow64FsRedirection(PVOID *OldValue);
BOOL WINAPI Wow64RevertWow64FsRedirection(PVOID OldValue);
BOOL WINAPI IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);

} // namespace kernel32
