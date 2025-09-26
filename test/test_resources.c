#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buffer[128];
    int copied = LoadStringA(GetModuleHandleA(NULL), 100, buffer, sizeof(buffer));
    if (copied <= 0) {
        printf("LoadString failed: %lu\n", GetLastError());
        return 1;
    }
    printf("STRING[100]=%s\n", buffer);

    HRSRC versionInfo = FindResourceA(NULL, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(RT_VERSION));
    if (!versionInfo) {
        printf("FindResource version failed: %lu\n", GetLastError());
        return 1;
    }
    DWORD versionSize = SizeofResource(NULL, versionInfo);
    if (!versionSize) {
        printf("SizeofResource failed: %lu\n", GetLastError());
        return 1;
    }
    printf("VERSION size=%lu\n", (unsigned long)versionSize);

    char modulePath[MAX_PATH];
    DWORD moduleLen = GetModuleFileNameA(NULL, modulePath, sizeof(modulePath));
    if (moduleLen == 0 || moduleLen >= sizeof(modulePath)) {
        printf("GetModuleFileNameA failed: %lu\n", GetLastError());
        return 1;
    }

    DWORD handle = 0;
    DWORD infoSize = GetFileVersionInfoSizeA(modulePath, &handle);
    if (!infoSize) {
        printf("GetFileVersionInfoSizeA failed: %lu\n", GetLastError());
        return 1;
    }

    char *infoBuffer = (char *)malloc(infoSize);
    if (!infoBuffer) {
        printf("malloc failed\n");
        return 1;
    }

    if (!GetFileVersionInfoA(modulePath, 0, infoSize, infoBuffer)) {
        printf("GetFileVersionInfoA failed: %lu\n", GetLastError());
        free(infoBuffer);
        return 1;
    }

    VS_FIXEDFILEINFO *fixedInfo = NULL;
    unsigned int fixedSize = 0;
    if (!VerQueryValueA(infoBuffer, "\\", (void **)&fixedInfo, &fixedSize)) {
        printf("VerQueryValueA root failed\n");
        free(infoBuffer);
        return 1;
    }
    printf("FILEVERSION=%u.%u.%u.%u\n",
           fixedInfo->dwFileVersionMS >> 16,
           fixedInfo->dwFileVersionMS & 0xFFFF,
           fixedInfo->dwFileVersionLS >> 16,
           fixedInfo->dwFileVersionLS & 0xFFFF);

    struct { WORD wLanguage; WORD wCodePage; } *translations = NULL;
    unsigned int transSize = 0;
    if (VerQueryValueA(infoBuffer, "\\VarFileInfo\\Translation", (void **)&translations, &transSize) &&
        translations && transSize >= sizeof(*translations)) {
        printf("Translation=%04X %04X\n", translations[0].wLanguage, translations[0].wCodePage);
        char subBlock[64];
        snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04X%04X\\ProductVersion",
                 translations[0].wLanguage, translations[0].wCodePage);
        char *productVersion = NULL;
        unsigned int pvSize = 0;
        printf("Querying %s\n", subBlock);
        if (VerQueryValueA(infoBuffer, subBlock, (void **)&productVersion, &pvSize) && productVersion) {
            printf("PRODUCTVERSION=%s\n", productVersion);
        } else {
            printf("ProductVersion lookup failed\n");
        }
    } else {
        printf("ProductVersion lookup failed\n");
    }

    free(infoBuffer);
    return 0;
}
