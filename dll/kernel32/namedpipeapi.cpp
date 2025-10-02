#include "namedpipeapi.h"

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

	FILE *readStream = fdopen(pipeFds[0], "rb");
	if (!readStream) {
		int savedErrno = errno ? errno : EINVAL;
		close(pipeFds[0]);
		close(pipeFds[1]);
		errno = savedErrno;
		setLastErrorFromErrno();
		return FALSE;
	}
	FILE *writeStream = fdopen(pipeFds[1], "wb");
	if (!writeStream) {
		int savedErrno = errno ? errno : EINVAL;
		fclose(readStream);
		close(pipeFds[1]);
		errno = savedErrno;
		setLastErrorFromErrno();
		return FALSE;
	}

	setvbuf(readStream, nullptr, _IONBF, 0);
	setvbuf(writeStream, nullptr, _IONBF, 0);

	HANDLE readHandle = files::allocFpHandle(readStream, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, true);
	HANDLE writeHandle = files::allocFpHandle(writeStream, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, true);
	if (!readHandle || !writeHandle) {
		fclose(readStream);
		fclose(writeStream);
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}

	*hReadPipe = readHandle;
	*hWritePipe = writeHandle;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
