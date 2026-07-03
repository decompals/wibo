#include "test_assert.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static int env_name_equals(const char *entry, const char *name) {
	size_t i = 0;
	while (name[i] != '\0') {
		if (entry[i] == '\0' || entry[i] == '=') {
			return 0;
		}
		if (tolower((unsigned char)entry[i]) != tolower((unsigned char)name[i])) {
			return 0;
		}
		i++;
	}
	return entry[i] == '=';
}

int main(void) {
	// Get the environment block
	LPCH env = GetEnvironmentStringsA();
	TEST_CHECK(env != NULL);

	// Parse the block: NULL-terminated strings, ending with a double NULL
	char *p = env;
	int foundPath = 0;
	int foundTmp = 0;
	int foundTemp = 0;
	while (*p != '\0') {
		if (env_name_equals(p, "PATH")) {
			foundPath = 1;
			char *pathValue = p + 5;
			// In Wibo, converted PATHs are Z:\...;Z:\...
			// So they must contain at least one ';'
			// They should NOT contain ':' as a delimiter, only within drive letters like Z:
			// This check is a simple heuristic.
			if (strchr(pathValue, ';') != NULL) {
				// Success: PATH converted to semicolon-delimited
			} else {
				TEST_CHECK_MSG(0, "PATH does not contain ';', value: %s", pathValue);
			}
		} else if (env_name_equals(p, "TMP")) {
			foundTmp = 1;
		} else if (env_name_equals(p, "TEMP")) {
			foundTemp = 1;
		}
		p += strlen(p) + 1;
	}

	TEST_CHECK(foundPath);
	TEST_CHECK(foundTmp);
	TEST_CHECK(foundTemp);

	FreeEnvironmentStringsA(env);

	char buffer[MAX_PATH];
	DWORD len = GetEnvironmentVariableA("TMP", buffer, sizeof(buffer));
	TEST_CHECK(len > 0 && len < sizeof(buffer));
	TEST_CHECK_MSG(strchr(buffer, '\\') != NULL, "TMP should be a Windows path, got: %s", buffer);

	len = GetEnvironmentVariableA("TEMP", buffer, sizeof(buffer));
	TEST_CHECK(len > 0 && len < sizeof(buffer));
	TEST_CHECK_MSG(strchr(buffer, '\\') != NULL, "TEMP should be a Windows path, got: %s", buffer);

	return EXIT_SUCCESS;
}
