#include "ioapiset.h"

#include "context.h"
#include "errors.h"
#include "internal.h"
#include "overlapped_util.h"
#include "synchapi.h"

#include <mutex>

namespace kernel32 {

BOOL WINAPI GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred,
								  BOOL bWait) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetOverlappedResult(%p, %p, %p, %d)\n", hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
	if (!lpOverlapped) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (bWait && lpOverlapped->Internal == STATUS_PENDING) {
		if (HANDLE waitHandle = kernel32::detail::normalizedOverlappedEventHandle(lpOverlapped)) {
			WaitForSingleObject(waitHandle, INFINITE);
		} else if (auto file = wibo::handles().getAs<FileObject>(hFile)) {
			std::unique_lock lk(file->m);
			file->overlappedCv.wait(lk, [&] { return lpOverlapped->Internal != STATUS_PENDING; });
		} else {
			setLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}
	}

	const auto status = static_cast<NTSTATUS>(lpOverlapped->Internal);
	if (status == STATUS_PENDING) {
		setLastError(ERROR_IO_INCOMPLETE);
		return FALSE;
	}

	if (lpNumberOfBytesTransferred) {
		*lpNumberOfBytesTransferred = static_cast<DWORD>(lpOverlapped->InternalHigh);
	}

	DWORD error = wibo::winErrorFromNtStatus(status);
	if (error == ERROR_SUCCESS) {
		return TRUE;
	}
	setLastError(error);
	return FALSE;
}

} // namespace kernel32
