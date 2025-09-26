#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "test_assert.h"

int main(void) {
    char buffer[128];
    int copied = LoadStringA(GetModuleHandleA(NULL), 100, buffer, sizeof(buffer));
    TEST_CHECK_MSG(copied > 0, "LoadStringA failed: %lu", (unsigned long)GetLastError());
    TEST_CHECK_EQ((int)strlen("Resource string 100"), copied);
    TEST_CHECK_STR_EQ("Resource string 100", buffer);

    HRSRC versionInfo = FindResourceA(NULL, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(RT_VERSION));
    TEST_CHECK_MSG(versionInfo != NULL, "FindResourceA version failed: %lu", (unsigned long)GetLastError());

    DWORD versionSize = SizeofResource(NULL, versionInfo);
    TEST_CHECK_MSG(versionSize != 0, "SizeofResource failed: %lu", (unsigned long)GetLastError());
    TEST_CHECK_EQ(364, (int)versionSize);

    char modulePath[MAX_PATH];
    DWORD moduleLen = GetModuleFileNameA(NULL, modulePath, sizeof(modulePath));
    TEST_CHECK_MSG(moduleLen > 0 && moduleLen < sizeof(modulePath),
                  "GetModuleFileNameA failed: %lu", (unsigned long)GetLastError());

    DWORD handle = 0;
    DWORD infoSize = GetFileVersionInfoSizeA(modulePath, &handle);
    TEST_CHECK_MSG(infoSize != 0, "GetFileVersionInfoSizeA failed: %lu", (unsigned long)GetLastError());

    char *infoBuffer = (char *)malloc(infoSize);
    TEST_CHECK_MSG(infoBuffer != NULL, "malloc(%lu) failed", (unsigned long)infoSize);

    TEST_CHECK_MSG(GetFileVersionInfoA(modulePath, 0, infoSize, infoBuffer) != 0,
                  "GetFileVersionInfoA failed: %lu", (unsigned long)GetLastError());

    VS_FIXEDFILEINFO *fixedInfo = NULL;
    unsigned int fixedSize = 0;
    TEST_CHECK_MSG(VerQueryValueA(infoBuffer, "\\", (void **)&fixedInfo, &fixedSize) != 0 &&
                      fixedInfo != NULL,
                  "VerQueryValueA root failed");
    TEST_CHECK_MSG(fixedSize >= sizeof(*fixedInfo),
                  "Unexpected VS_FIXEDFILEINFO size: %u", fixedSize);
    TEST_CHECK_EQ(1, (int)(fixedInfo->dwFileVersionMS >> 16));
    TEST_CHECK_EQ(2, (int)(fixedInfo->dwFileVersionMS & 0xFFFF));
    TEST_CHECK_EQ(3, (int)(fixedInfo->dwFileVersionLS >> 16));
    TEST_CHECK_EQ(4, (int)(fixedInfo->dwFileVersionLS & 0xFFFF));

    struct { WORD wLanguage; WORD wCodePage; } *translations = NULL;
    unsigned int transSize = 0;
    TEST_CHECK_MSG(VerQueryValueA(infoBuffer, "\\VarFileInfo\\Translation",
                                 (void **)&translations, &transSize) != 0 &&
                      translations != NULL,
                  "Translation lookup failed");
    TEST_CHECK_MSG(transSize >= sizeof(*translations),
                  "Translation block too small: %u", transSize);
    TEST_CHECK_EQ(0x0409, translations[0].wLanguage);
    TEST_CHECK_EQ(0x04B0, translations[0].wCodePage);

    char subBlock[64];
    int subLen = snprintf(subBlock, sizeof(subBlock),
                          "\\StringFileInfo\\%04X%04X\\ProductVersion",
                          translations[0].wLanguage, translations[0].wCodePage);
    TEST_CHECK_MSG(subLen > 0 && (size_t)subLen < sizeof(subBlock),
                  "Failed to build ProductVersion path");

    char *productVersion = NULL;
    unsigned int pvSize = 0;
    TEST_CHECK_MSG(VerQueryValueA(infoBuffer, subBlock, (void **)&productVersion, &pvSize) != 0 &&
                      productVersion != NULL,
                  "ProductVersion lookup failed");
    TEST_CHECK_STR_EQ("1.2.3-test", productVersion);

    free(infoBuffer);
    puts("resource metadata validated");
    return EXIT_SUCCESS;
}
