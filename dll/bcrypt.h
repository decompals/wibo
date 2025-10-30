#pragma once

#include "types.h"

using BCRYPT_ALG_HANDLE = PVOID;

namespace bcrypt {

NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
BOOL WINAPI ProcessPrng(PBYTE pbData, SIZE_T cbData);

} // namespace bcrypt
