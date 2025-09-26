#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#include "test_assert.h"

int main(void) {
    typedef int(__stdcall *add_numbers_fn)(int, int);
    typedef int(__stdcall *was_attached_fn)(void);

    HMODULE mod = LoadLibraryA("external_exports.dll");
    TEST_CHECK_MSG(mod != NULL, "LoadLibraryA failed: %lu", (unsigned long)GetLastError());

    FARPROC raw_add_numbers = GetProcAddress(mod, "add_numbers@8");
    FARPROC raw_was_attached = GetProcAddress(mod, "was_attached@0");
    TEST_CHECK_MSG(raw_add_numbers != NULL, "GetProcAddress(add_numbers@8) failed: %lu", (unsigned long)GetLastError());
    TEST_CHECK_MSG(raw_was_attached != NULL, "GetProcAddress(was_attached@0) failed: %lu", (unsigned long)GetLastError());

    add_numbers_fn add_numbers = (add_numbers_fn)(uintptr_t)raw_add_numbers;
    was_attached_fn was_attached = (was_attached_fn)(uintptr_t)raw_was_attached;

    int sum = add_numbers(2, 40);
    int attached = was_attached();

    TEST_CHECK_EQ(42, sum);
    TEST_CHECK_EQ(1, attached);

    TEST_CHECK_MSG(FreeLibrary(mod) != 0, "FreeLibrary failed: %lu", (unsigned long)GetLastError());

    printf("external_exports: sum=%d attached=%d\n", sum, attached);
    return EXIT_SUCCESS;
}
