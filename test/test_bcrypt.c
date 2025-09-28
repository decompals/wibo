#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <ntstatus.h>

#include "test_assert.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static void expect_success(NTSTATUS status) {
	TEST_CHECK_MSG(NT_SUCCESS(status), "Expected success NTSTATUS, got 0x%08lx", (unsigned long)status);
}

int main(void) {
	UCHAR temp[32] = {0};
	const UCHAR zero_block[32] = {0};
	NTSTATUS status = BCryptGenRandom(NULL, temp, sizeof(temp), 0);
	TEST_CHECK_EQ(STATUS_INVALID_HANDLE, status);

	UCHAR first[32] = {0};
	status = BCryptGenRandom(NULL, first, sizeof(first), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	expect_success(status);
	TEST_CHECK_MSG(memcmp(first, zero_block, sizeof(first)) != 0,
				   "BCryptGenRandom with system RNG flag left buffer zeroed");

	UCHAR second[32] = {0};
	status = BCryptGenRandom(NULL, second, sizeof(second), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	expect_success(status);
	TEST_CHECK_MSG(memcmp(second, zero_block, sizeof(second)) != 0,
				   "BCryptGenRandom produced zeroed buffer on repeat call");
	TEST_CHECK_MSG(memcmp(first, second, sizeof(first)) != 0,
				   "BCryptGenRandom produced identical buffers across calls");

	UCHAR entropy_buffer[32];
	UCHAR entropy_original[32];
	memset(entropy_buffer, 0x5a, sizeof(entropy_buffer));
	memcpy(entropy_original, entropy_buffer, sizeof(entropy_buffer));
	status = BCryptGenRandom(NULL, entropy_buffer, sizeof(entropy_buffer),
							BCRYPT_RNG_USE_ENTROPY_IN_BUFFER | BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	expect_success(status);
	TEST_CHECK_MSG(memcmp(entropy_buffer, entropy_original, sizeof(entropy_buffer)) != 0,
				   "Entropy flag did not modify buffer");

	status = BCryptGenRandom((BCRYPT_ALG_HANDLE)0x1, first, sizeof(first), 0);
	TEST_CHECK_EQ(STATUS_NOT_IMPLEMENTED, status);

	status = BCryptGenRandom(NULL, first, sizeof(first), 0x4);
	TEST_CHECK_EQ(STATUS_INVALID_HANDLE, status);

	status = BCryptGenRandom((BCRYPT_ALG_HANDLE)0x1, first, sizeof(first), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	TEST_CHECK_EQ(STATUS_NOT_IMPLEMENTED, status);

	status = BCryptGenRandom(NULL, NULL, sizeof(first), 0);
	TEST_CHECK_EQ(STATUS_INVALID_HANDLE, status);

	status = BCryptGenRandom(NULL, NULL, 0, 0);
	TEST_CHECK_EQ(STATUS_INVALID_HANDLE, status);

	printf("bcrypt_gen_random: passed\n");
	return EXIT_SUCCESS;
}
