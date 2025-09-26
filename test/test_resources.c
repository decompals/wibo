#include <windows.h>
#include <stdio.h>

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
    return 0;
}
