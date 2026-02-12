#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "test_assert.h"

/* Function pointer types for mspdb exports */
typedef int(__cdecl *PDBExportValidateInterface_fn)(DWORD intv);
typedef int(__cdecl *PDBOpen2W_fn)(LPCWSTR wszPDB, LPCSTR szMode, LONG *pec,
                                   LPWSTR wszError, UINT cchErrMax, void **ppPDB);
typedef int(__cdecl *PDBCommit_fn)(void *pPDB);
typedef int(__cdecl *PDBClose_fn)(void *pPDB);
typedef LONG(__cdecl *StreamQueryCb_fn)(void *pStream);
typedef int(__cdecl *StreamAppend_fn)(void *pStream, void *pvData, LONG cbData);
typedef int(__cdecl *StreamRelease_fn)(void *pStream);

int main(void) {
    /* 1. LoadLibraryA resolves to the wibo builtin module */
    HMODULE mod = LoadLibraryA("mspdb80.dll");
    TEST_CHECK_MSG(mod != NULL, "LoadLibraryA(mspdb80.dll) failed: %lu",
                   (unsigned long)GetLastError());

    /* 2. GetProcAddress finds the C-style exports */
    FARPROC raw_validate = GetProcAddress(mod, "PDBExportValidateInterface");
    FARPROC raw_open = GetProcAddress(mod, "PDBOpen2W");
    FARPROC raw_commit = GetProcAddress(mod, "PDBCommit");
    FARPROC raw_close = GetProcAddress(mod, "PDBClose");
    FARPROC raw_querycb = GetProcAddress(mod, "StreamQueryCb");
    FARPROC raw_append = GetProcAddress(mod, "StreamAppend");
    FARPROC raw_release = GetProcAddress(mod, "StreamRelease");

    TEST_CHECK_MSG(raw_validate != NULL, "GetProcAddress(PDBExportValidateInterface) failed");
    TEST_CHECK_MSG(raw_open != NULL, "GetProcAddress(PDBOpen2W) failed");
    TEST_CHECK_MSG(raw_commit != NULL, "GetProcAddress(PDBCommit) failed");
    TEST_CHECK_MSG(raw_close != NULL, "GetProcAddress(PDBClose) failed");
    TEST_CHECK_MSG(raw_querycb != NULL, "GetProcAddress(StreamQueryCb) failed");
    TEST_CHECK_MSG(raw_append != NULL, "GetProcAddress(StreamAppend) failed");
    TEST_CHECK_MSG(raw_release != NULL, "GetProcAddress(StreamRelease) failed");

    PDBExportValidateInterface_fn validate_fn =
        (PDBExportValidateInterface_fn)(uintptr_t)raw_validate;
    PDBOpen2W_fn open_fn = (PDBOpen2W_fn)(uintptr_t)raw_open;
    PDBCommit_fn commit_fn = (PDBCommit_fn)(uintptr_t)raw_commit;
    PDBClose_fn close_fn = (PDBClose_fn)(uintptr_t)raw_close;
    StreamQueryCb_fn querycb_fn = (StreamQueryCb_fn)(uintptr_t)raw_querycb;
    StreamAppend_fn append_fn = (StreamAppend_fn)(uintptr_t)raw_append;
    StreamRelease_fn release_fn = (StreamRelease_fn)(uintptr_t)raw_release;

    /* 3. PDBExportValidateInterface(20091201) returns 1 */
    int valid = validate_fn(20091201);
    TEST_CHECK_EQ(1, valid);

    /* 4. PDBOpen2W returns 1, sets ec=0, ppPDB!=NULL */
    LONG ec = -1;
    void *ppPDB = NULL;
    int opened = open_fn(L"test.pdb", "w", &ec, NULL, 0, &ppPDB);
    TEST_CHECK_EQ(1, opened);
    TEST_CHECK_EQ(0, ec);
    TEST_CHECK_MSG(ppPDB != NULL, "PDBOpen2W did not return a PDB handle");

    /* 5. Vtable dispatch: the PDB handle is a COM-style object whose first
     *    dword is a vtable pointer. This tests the full chain that breaks on
     *    64-bit if objects aren't in 32-bit addressable memory:
     *    object ptr -> vptr -> stub code -> return value */
    {
        /* __thiscall: this in ECX, no stack args for slot 0 */
        typedef int (__attribute__((thiscall)) *QueryInterfaceVersion_fn)(void *thisPtr);
        typedef int (__attribute__((thiscall)) *QueryAge_fn)(void *thisPtr);
        /* __thiscall: this in ECX, 2 stack args for OpenDBI (slot 7) */
        typedef int (__attribute__((thiscall)) *OpenDBI_fn)(void *thisPtr,
            const char *szTarget, const char *szMode, void **ppdbi);

        /* Read vtable pointer from the PDB object */
        DWORD *vtable = *(DWORD **)ppPDB;
        TEST_CHECK_MSG(vtable != NULL, "PDB object vtable pointer is NULL");

        /* Slot 0: QueryInterfaceVersion() -> 20091201 */
        QueryInterfaceVersion_fn queryIV =
            (QueryInterfaceVersion_fn)(uintptr_t)vtable[0];
        int intv = queryIV(ppPDB);
        TEST_CHECK_EQ(20091201, intv);

        /* Slot 5: QueryAge() -> 1 */
        QueryAge_fn queryAge = (QueryAge_fn)(uintptr_t)vtable[5];
        int age = queryAge(ppPDB);
        TEST_CHECK_EQ(1, age);

        /* Slot 7: OpenDBI(szTarget, szMode, DBI**) -> 1, writes DBI ptr */
        void *pDBI = NULL;
        OpenDBI_fn openDBI = (OpenDBI_fn)(uintptr_t)vtable[7];
        int dbiOk = openDBI(ppPDB, "target", "r", &pDBI);
        TEST_CHECK_EQ(1, dbiOk);
        TEST_CHECK_MSG(pDBI != NULL, "OpenDBI did not return a DBI handle");

        /* DBI object should also have a valid vtable - test dispatch */
        DWORD *dbiVtable = *(DWORD **)pDBI;
        TEST_CHECK_MSG(dbiVtable != NULL, "DBI object vtable pointer is NULL");

        /* DBI slot 0: QueryImplementationVersion() -> 20091201 */
        QueryInterfaceVersion_fn dbiQueryIV =
            (QueryInterfaceVersion_fn)(uintptr_t)dbiVtable[0];
        int dbiImpv = dbiQueryIV(pDBI);
        TEST_CHECK_EQ(20091201, dbiImpv);
    }

    /* 6. PDBCommit returns 1 */
    int committed = commit_fn(ppPDB);
    TEST_CHECK_EQ(1, committed);

    /* 7. PDBClose returns 1 */
    int closed = close_fn(ppPDB);
    TEST_CHECK_EQ(1, closed);

    /* 8. Stream functions */
    void *fakeStream = (void *)(uintptr_t)0x12345678;
    LONG cb = querycb_fn(fakeStream);
    TEST_CHECK_EQ(0, cb);

    char data[] = "hello";
    int appended = append_fn(fakeStream, data, sizeof(data));
    TEST_CHECK_EQ(1, appended);

    int released = release_fn(fakeStream);
    TEST_CHECK_EQ(1, released);

    printf("mspdb: passed\n");
    return EXIT_SUCCESS;
}
