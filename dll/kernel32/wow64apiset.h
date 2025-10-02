#pragma once

#include "common.h"

namespace kernel32 {

BOOL WIN_FUNC Wow64DisableWow64FsRedirection(PVOID *OldValue);
BOOL WIN_FUNC Wow64RevertWow64FsRedirection(PVOID OldValue);
BOOL WIN_FUNC IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);

} // namespace kernel32
