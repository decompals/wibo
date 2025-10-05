#include "namedpipeapi.h"

#include "common.h"
#include "errors.h"
#include "fileapi.h"
#include "files.h"
#include "handles.h"
#include "internal.h"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

namespace kernel32 {

namespace {

void configureInheritability(int fd, bool inherit) {
	if (fd < 0) {
		return;
	}
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		return;
	}
	if (inherit) {
		flags &= ~FD_CLOEXEC;
	} else {
		flags |= FD_CLOEXEC;
	}
	fcntl(fd, F_SETFD, flags);
}

} // namespace

BOOL WIN_FUNC CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("CreatePipe(%p, %p, %p, %u)\n", hReadPipe, hWritePipe, lpPipeAttributes, nSize);
	if (!hReadPipe || !hWritePipe) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*hReadPipe = nullptr;
	*hWritePipe = nullptr;

	int pipeFds[2];
	if (pipe(pipeFds) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}

	bool inheritHandles = lpPipeAttributes && lpPipeAttributes->bInheritHandle;
	configureInheritability(pipeFds[0], inheritHandles);
	configureInheritability(pipeFds[1], inheritHandles);

	if (nSize != 0) {
		// Best-effort adjustment; ignore failures as recommended by docs.
		fcntl(pipeFds[0], F_SETPIPE_SZ, static_cast<int>(nSize));
		fcntl(pipeFds[1], F_SETPIPE_SZ, static_cast<int>(nSize));
	}

	auto readObj = make_pin<FileObject>(pipeFds[0]);
	readObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	auto writeObj = make_pin<FileObject>(pipeFds[1]);
	writeObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	*hReadPipe = wibo::handles().alloc(std::move(readObj), FILE_GENERIC_READ, 0);
	*hWritePipe = wibo::handles().alloc(std::move(writeObj), FILE_GENERIC_WRITE, 0);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
