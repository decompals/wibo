#pragma once

#include "types.h"

namespace mspdb {

// PDB open/create functions (imported by link.exe main module)
int CDECL PDB_Open2W(LPCWSTR wszPDB, LPCSTR szMode, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB);
int CDECL PDB_Open3W(LPCWSTR wszPDB, LPCSTR szMode, DWORD dwSig, void *pcsig70, DWORD dwAge, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB);
int CDECL PDB_OpenValidate5(LPCWSTR wszPDB, LPCWSTR wszSearchPath, void *pvClient, void *pfnQueryCallback, void *pfnNoteCallback, DWORD dwUnused, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB);
int CDECL PDBExportValidateInterface(DWORD intv);
DWORD CDECL SigForPbCb(void *pb, DWORD cb);
LPCSTR CDECL SzCanonFilename(LPCSTR szFilename);

// PDB management functions (imported by linker supplementary module)
int CDECL PDBOpen2W_C(LPCWSTR wszPDB, LPCSTR szMode, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB);
int CDECL PDBOpenStreamEx(void *pPDB, LPCSTR szStream, DWORD dwFlags, void **ppStream);
int CDECL PDBCommit(void *pPDB);
int CDECL PDBClose(void *pPDB);

// NameMap
int CDECL NameMap_open(void *pPDB, int fWrite, void **ppNameMap);

// Stream functions
int CDECL StreamAppend(void *pStream, void *pvData, LONG cbData);
LONG CDECL StreamQueryCb(void *pStream);
int CDECL StreamRead(void *pStream, LONG off, void *pvData, LONG *pcbData);
int CDECL StreamRelease(void *pStream);
int CDECL StreamReplace(void *pStream, void *pvData, LONG cbData);
int CDECL StreamTruncate(void *pStream, LONG cbData);
int CDECL StreamWrite(void *pStream, LONG off, void *pvData, LONG cbData);

} // namespace mspdb
