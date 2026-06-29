#include "test_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main(void) {
    // Get the environment block
    LPCH env = GetEnvironmentStringsA();
    TEST_CHECK(env != NULL);

    // Parse the block: NULL-terminated strings, ending with a double NULL
    char* p = env;
    int foundPath = 0;
    while (*p != '\0') {
        if (strncmp(p, "PATH=", 5) == 0) {
            foundPath = 1;
            char* pathValue = p + 5;
            // In Wibo, converted PATHs are Z:\...;Z:\...
            // So they must contain at least one ';'
            // They should NOT contain ':' as a delimiter, only within drive letters like Z:
            // This check is a simple heuristic.
            if (strchr(pathValue, ';') != NULL) {
                // Success: PATH converted to semicolon-delimited
            } else {
                TEST_CHECK_MSG(0, "PATH does not contain ';', value: %s", pathValue);
            }
        }
        p += strlen(p) + 1;
    }

    TEST_CHECK(foundPath);

    FreeEnvironmentStringsA(env);
    return EXIT_SUCCESS;
}
