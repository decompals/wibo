#include "test_assert.h"
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

static void test_startup_gethostname_cleanup(void) {
	WSADATA data;
	memset(&data, 0, sizeof(data));

	TEST_CHECK_EQ(0, WSAStartup(MAKEWORD(1, 1), &data));
	TEST_CHECK_EQ(1, data.wVersion & 0xff);
	TEST_CHECK_EQ(1, (data.wVersion >> 8) & 0xff);

	char hostname[256] = {0};
	TEST_CHECK_EQ(0, gethostname(hostname, sizeof(hostname)));
	TEST_CHECK(hostname[0] != '\0');

	TEST_CHECK_EQ(0, WSACleanup());
}

int main(void) {
	test_startup_gethostname_cleanup();
	return EXIT_SUCCESS;
}
