#include "ioapiset.h"

#include "errors.h"
#include "synchapi.h"

namespace kernel32 {

BOOL WIN_FUNC GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred,
								  BOOL bWait) {
	DEBUG_LOG("GetOverlappedResult(%p, %p, %p, %d)\n", hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
	(void)hFile;
	if (!lpOverlapped) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (bWait && lpOverlapped->Internal == STATUS_PENDING && lpOverlapped->hEvent) {
		WaitForSingleObject(lpOverlapped->hEvent, INFINITE);
	}

	const auto status = static_cast<NTSTATUS>(lpOverlapped->Internal);
	if (status == STATUS_PENDING) {
		wibo::lastError = ERROR_IO_INCOMPLETE;
		return FALSE;
	}

	if (lpNumberOfBytesTransferred) {
		*lpNumberOfBytesTransferred = static_cast<DWORD>(lpOverlapped->InternalHigh);
	}

	if (status == STATUS_SUCCESS) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (status == STATUS_END_OF_FILE) {
		wibo::lastError = ERROR_HANDLE_EOF;
		return FALSE;
	}

	wibo::lastError = status;
	return FALSE;
}

} // namespace kernel32
