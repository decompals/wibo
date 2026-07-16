#include <stdarg.h>
#include <windows.h>

#include "test_assert.h"

static DWORD format_message(LPCSTR message, LPSTR buffer, DWORD size, ...) {
	va_list arguments;
	DWORD result;

	va_start(arguments, size);
	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING, message, 0, 0, buffer, size, &arguments);
	va_end(arguments);
	return result;
}

int main(void) {
	static const char expected_message[] = "second then first";
	char buffer[256];
	DWORD result;

	memset(buffer, 'x', sizeof(buffer));
	result = format_message("%2 then %1", buffer, sizeof(buffer), "first", "second");
	TEST_CHECK_EQ(strlen(expected_message), result);
	TEST_CHECK_EQ(0, strcmp(expected_message, buffer));
	return 0;
}
