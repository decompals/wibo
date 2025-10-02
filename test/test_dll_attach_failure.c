#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "test_assert.h"

int main(void) {
    SetLastError(0);
    HMODULE mod = LoadLibraryA("dll_attach_failure.dll");
    DWORD error = GetLastError();

    TEST_CHECK_MSG(mod == NULL, "LoadLibraryA unexpectedly succeeded: %p", mod);
    TEST_CHECK_EQ(ERROR_DLL_INIT_FAILED, error);

    printf("dll_attach_failure: error=%lu\n", (unsigned long)error);
    return EXIT_SUCCESS;
}
