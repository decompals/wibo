#include <windows.h>

#include "test_assert.h"

#ifndef ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX
#define ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX 0x00000001
#endif

#ifndef ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION
typedef struct _ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION {
	ULONG Size;
	ULONG Flags;
	ULONG TotalPathLength;
	ULONG PathSegmentCount;
	ULONG PathSegmentOffset;
} ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION;
#endif

static BOOL isRunningUnderWine(void) {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	return hNtdll != NULL && GetProcAddress(hNtdll, "wine_get_version") != NULL;
}

static void check_success_w(void) {
	ACTCTX_SECTION_KEYED_DATA data = { 0 };
	data.cbSize = sizeof(data);
	SetLastError(0);
	BOOL ok = FindActCtxSectionStringW(0, NULL, ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
									 L"msvcr80.dll", &data);
	TEST_CHECK(ok);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());
	TEST_CHECK_EQ(1u, data.ulDataFormatVersion);
	TEST_CHECK((data.ulFlags & ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX) != 0);
	TEST_CHECK(data.lpData != NULL);
	TEST_CHECK(data.ulLength >= sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION));
	TEST_CHECK(data.hActCtx == NULL);
	TEST_CHECK_EQ(1u, data.ulAssemblyRosterIndex);
}

static void check_success_a(void) {
	ACTCTX_SECTION_KEYED_DATA data = { 0 };
	data.cbSize = sizeof(data);
	SetLastError(0);
	BOOL ok = FindActCtxSectionStringA(FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, NULL,
									 ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
									 "msvcp80.dll", &data);
	TEST_CHECK(ok);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());
	TEST_CHECK((data.ulFlags & ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX) != 0);
	TEST_CHECK(data.lpData != NULL);
	TEST_CHECK(data.hActCtx != NULL);
	TEST_CHECK_EQ(1u, data.ulAssemblyRosterIndex);
}

static void check_invalid_parameters(void) {
	ACTCTX_SECTION_KEYED_DATA data = { 0 };
	data.cbSize = sizeof(data);
	GUID fakeGuid = {0};
	SetLastError(0);
	BOOL ok = FindActCtxSectionStringW(0, &fakeGuid, ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
									 L"msvcr80.dll", &data);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	ACTCTX_SECTION_KEYED_DATA sized = { 0 };
	sized.cbSize = sizeof(data) - 4;
	SetLastError(0);
	ok = FindActCtxSectionStringW(0, NULL, ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
							L"msvcr80.dll", &sized);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());

	ACTCTX_SECTION_KEYED_DATA flags = { 0 };
	flags.cbSize = sizeof(flags);
	SetLastError(0);
	ok = FindActCtxSectionStringW(0x2, NULL, ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
							L"msvcr80.dll", &flags);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
}

static void check_missing_entries(void) {
	ACTCTX_SECTION_KEYED_DATA data = { 0 };
	data.cbSize = sizeof(data);
	SetLastError(0);
	BOOL ok = FindActCtxSectionStringW(0, NULL, ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
									 L"totally_missing.dll", &data);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_SXS_KEY_NOT_FOUND, GetLastError());

	ACTCTX_SECTION_KEYED_DATA wrongSection = { 0 };
	wrongSection.cbSize = sizeof(wrongSection);
	SetLastError(0);
	ok = FindActCtxSectionStringW(0, NULL, ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION,
							L"msvcr80.dll", &wrongSection);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_SXS_KEY_NOT_FOUND, GetLastError());
}

int main(void) {
	if (isRunningUnderWine()) {
		printf("test_actctx: skipping under wine\n");
		return 0;
	}
	check_success_w();
	check_success_a();
	check_invalid_parameters();
	check_missing_entries();
	return 0;
}
