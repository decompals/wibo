#include <windows.h>
#include <stdio.h>

int main(void) {
typedef int (__stdcall *add_numbers_fn)(int, int);
typedef int (__stdcall *was_attached_fn)(void);

	HMODULE mod = LoadLibraryA("external_exports.dll");
	if (!mod) {
		printf("LoadLibraryA failed: %lu\n", GetLastError());
		return 1;
	}

	add_numbers_fn add_numbers = (add_numbers_fn)GetProcAddress(mod, "add_numbers@8");
	was_attached_fn was_attached = (was_attached_fn)GetProcAddress(mod, "was_attached@0");
	if (!add_numbers || !was_attached) {
		printf("GetProcAddress failed: %lu\n", GetLastError());
		return 1;
	}

	int sum = add_numbers(2, 40);
	int attached = was_attached();

	printf("sum=%d attached=%d\n", sum, attached);

	if (!FreeLibrary(mod)) {
		printf("FreeLibrary failed: %lu\n", GetLastError());
		return 1;
	}

	return (sum == 42 && attached == 1) ? 0 : 2;
}
