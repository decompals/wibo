#pragma once

#include "types.h"

using ALG_ID = DWORD;
using HCRYPTPROV = ULONG_PTR;
using HCRYPTKEY = ULONG_PTR;
using HCRYPTHASH = ULONG_PTR;

constexpr ALG_ID CALG_MD5 = 0x00008003;
constexpr ALG_ID CALG_SHA1 = 0x00008004;

constexpr DWORD HP_ALGID = 0x00000001;
constexpr DWORD HP_HASHVAL = 0x00000002;
constexpr DWORD HP_HASHSIZE = 0x00000004;

namespace advapi32 {

BOOL WINAPI CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL WINAPI CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType,
								 DWORD dwFlags);
BOOL WINAPI CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
BOOL WINAPI CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
BOOL WINAPI CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL WINAPI CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
BOOL WINAPI CryptDestroyHash(HCRYPTHASH hHash);

} // namespace advapi32
