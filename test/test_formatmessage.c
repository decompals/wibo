#include <windows.h>

#include "test_assert.h"

static void test_common_system_messages(void) {
	static const DWORD codes[] = {
		10,	   11,	  16,	 17,	20,	   23,	  25,	 27,	33,	   39,	  52,	 53,	54,	   55,	 58,
		59,	   64,	  65,	 67,	82,	   85,	  86,	 89,	121,   124,	  131,	 132,	158,   160,	 161,
		164,   167,	  170,	 216,	230,   233,	  288,	 299,	534,   535,	  536,	 1001,	1006,  1008, 1009,
		1010,  1011,  1012,	 1013,	1014,  1015,  1016,	 1017,	1018,  1114,  1117,	 1130,	1131,  1157, 1223,
		1225,  1231,  1232,	 1236,	1300,  1314,  1326,	 1450,	1451,  1452,  1453,	 1454,	1455,  1460, 1816,
		10004, 10009, 10013, 10014, 10022, 10024, 10049, 10054, 10061, 11001, 11002, 11003, 11004,
	};

	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
		char buffer[512] = {0};
		SetLastError(ERROR_ACCESS_DENIED);
		DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, codes[i],
									  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, sizeof(buffer), NULL);
		TEST_CHECK_MSG(result >= 2, "No system message for error %lu (last error %lu)", codes[i], GetLastError());
		TEST_CHECK_EQ(result, strlen(buffer));
		TEST_CHECK_STR_EQ("\r\n", buffer + result - 2);
		TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());

		char hresult_buffer[512] = {0};
		DWORD hresult_length =
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0x80070000 | codes[i],
						   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), hresult_buffer, sizeof(hresult_buffer), NULL);
		TEST_CHECK_EQ(result, hresult_length);
		TEST_CHECK_STR_EQ(buffer, hresult_buffer);
	}
}

static void test_system_messages(void) {
	static const struct {
		DWORD id;
		const char *text;
	} cases[] = {
		{ERROR_ACCESS_DENIED, "Access denied.\r\n"},
		{ERROR_FILE_NOT_FOUND, "File not found.\r\n"},
		{0x80070005, "Access denied.\r\n"},
		{ERROR_NOT_SAME_DEVICE, "Not same device.\r\n"},
		{ERROR_NO_SYSTEM_RESOURCES, "No system resources.\r\n"},
		{WSAECONNRESET, "Connection reset by peer.\r\n"},
		{WSAECONNREFUSED, "Connection refused.\r\n"},
		{WSAHOST_NOT_FOUND, "Host not found.\r\n"},
		{ERROR_ARENA_TRASHED, "Memory trashed.\r\n"},
		{ERROR_INVALID_WINDOW_HANDLE, "Invalid window handle.\r\n"},
		{E_NOTIMPL, "Not implemented.\r\n"},
		{E_FAIL, "Call failed.\r\n"},
		{0x800B0100, "No Signature found in file.\r\n"},
		{0x887A0001, "Invalid call.\r\n"},
	};
	static const DWORD flags[] = {
		FORMAT_MESSAGE_FROM_SYSTEM,
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY,
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		for (size_t j = 0; j < sizeof(flags) / sizeof(flags[0]); ++j) {
			char buffer[256] = {0};
			DWORD result = FormatMessageA(flags[j], NULL, cases[i].id, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
										  buffer, sizeof(buffer), NULL);

			TEST_CHECK_EQ(strlen(cases[i].text), result);
			TEST_CHECK_STR_EQ(cases[i].text, buffer);
			TEST_CHECK_EQ(result, strlen(buffer));
		}
	}
}

static void test_unknown_message(void) {
	static const DWORD codes[] = {0xdeadbeef,	WSAEWOULDBLOCK,	   WSAEADDRINUSE,
								  WSAETIMEDOUT, WSANOTINITIALISED, WSAEDISCON};
	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
		char buffer[256];
		SetLastError(ERROR_SUCCESS);
		DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, codes[i],
									  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, sizeof(buffer), NULL);
		DWORD error = GetLastError();

		TEST_CHECK_EQ(0, result);
		TEST_CHECK_EQ(ERROR_MR_MID_NOT_FOUND, error);
	}
}

static void test_small_buffer(void) {
	char buffer[8];
	SetLastError(ERROR_SUCCESS);
	DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_ACCESS_DENIED,
								  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, sizeof(buffer), NULL);
	DWORD error = GetLastError();

	TEST_CHECK_EQ(0, result);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, error);
}

static void test_exact_buffer_size(void) {
	const char expected[] = "Access denied.\r\n";
	char buffer[sizeof(expected)];
	memset(buffer, 'x', sizeof(buffer));
	SetLastError(ERROR_SUCCESS);
	DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_ACCESS_DENIED,
								  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, sizeof(expected) - 1, NULL);
	DWORD error = GetLastError();

	TEST_CHECK_EQ(0, result);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, error);
	TEST_CHECK_EQ('x', buffer[sizeof(buffer) - 1]);

	memset(buffer, 'x', sizeof(buffer));
	result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_ACCESS_DENIED,
							MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, sizeof(buffer), NULL);

	TEST_CHECK_EQ(sizeof(expected) - 1, result);
	TEST_CHECK_EQ('\0', buffer[sizeof(buffer) - 1]);
	TEST_CHECK_STR_EQ(expected, buffer);
}

static void test_invalid_parameters(void) {
	static const struct {
		DWORD flags;
		DWORD size;
		DWORD error;
	} cases[] = {
		{FORMAT_MESSAGE_IGNORE_INSERTS, 256, ERROR_INVALID_PARAMETER},
		{FORMAT_MESSAGE_FROM_SYSTEM, 32768, ERROR_INVALID_PARAMETER},
		{FORMAT_MESSAGE_FROM_SYSTEM, 0, ERROR_INSUFFICIENT_BUFFER},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		char buffer[256];
		SetLastError(ERROR_SUCCESS);
		DWORD result = FormatMessageA(cases[i].flags, NULL, ERROR_ACCESS_DENIED,
									  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, cases[i].size, NULL);
		TEST_CHECK_EQ(0, result);
		TEST_CHECK_EQ(cases[i].error, GetLastError());
	}
}

static void test_ignored_arguments(void) {
	const char expected[] = "Access denied.\r\n";
	char buffer[256];
	SetLastError(ERROR_ACCESS_DENIED);
	DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY, NULL, ERROR_ACCESS_DENIED,
								  0, buffer, sizeof(buffer), (va_list *)(ULONG_PTR)1);
	TEST_CHECK_EQ(sizeof(expected) - 1, result);
	TEST_CHECK_STR_EQ(expected, buffer);
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
}

static void test_max_width(void) {
	static const DWORD widths[] = {20, 80, FORMAT_MESSAGE_MAX_WIDTH_MASK};
	const char expected[] = "Access denied. ";
	for (size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); ++i) {
		char buffer[sizeof(expected) + 1];
		memset(buffer, 'x', sizeof(buffer));
		SetLastError(ERROR_SUCCESS);
		DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | widths[i], NULL,
									  ERROR_ACCESS_DENIED, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer,
									  sizeof(expected) - 1, NULL);
		TEST_CHECK_EQ(0, result);
		TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());

		SetLastError(ERROR_ACCESS_DENIED);
		result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | widths[i], NULL,
								ERROR_ACCESS_DENIED, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer,
								sizeof(expected), NULL);
		TEST_CHECK_EQ(sizeof(expected) - 1, result);
		TEST_CHECK_STR_EQ(expected, buffer);
		TEST_CHECK_EQ('x', buffer[sizeof(expected)]);
		TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	}
}

int main(void) {
	test_common_system_messages();
	test_system_messages();
	test_unknown_message();
	test_small_buffer();
	test_exact_buffer_size();
	test_invalid_parameters();
	test_ignored_arguments();
	test_max_width();
	return 0;
}
