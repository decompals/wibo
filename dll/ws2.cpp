#include "ws2.h"

#include "common.h"
#include "context.h"
#include "modules.h"

#include <cstring>
#include <unistd.h>

namespace {

constexpr int SOCKET_ERROR = -1;
constexpr int WSAEFAULT = 10014;
constexpr int WSAHOST_NOT_FOUND = 11001;
constexpr int WSANOTINITIALISED = 10093;

thread_local int g_lastError = 0;
int g_startupCount = 0;

void setLastError(int error) { g_lastError = error; }

WORD makeVersion(BYTE major, BYTE minor) { return static_cast<WORD>(major | (minor << 8)); }

bool requireStarted() {
	if (g_startupCount > 0) {
		return true;
	}
	setLastError(WSANOTINITIALISED);
	return false;
}

} // namespace

namespace ws2 {

int WINAPI WSAStartup(WORD wVersionRequired, WSADATA *lpWSAData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WSAStartup(0x%x, %p)\n", wVersionRequired, lpWSAData);
	if (!lpWSAData) {
		setLastError(WSAEFAULT);
		return WSAEFAULT;
	}

	std::memset(lpWSAData, 0, sizeof(*lpWSAData));
	lpWSAData->wVersion = wVersionRequired;
	lpWSAData->wHighVersion = makeVersion(2, 2);
	std::strncpy(lpWSAData->szDescription, "wibo fake Winsock", sizeof(lpWSAData->szDescription) - 1);
	std::strncpy(lpWSAData->szSystemStatus, "Running", sizeof(lpWSAData->szSystemStatus) - 1);
	lpWSAData->iMaxSockets = 0x7fff;
	lpWSAData->iMaxUdpDg = 65467; // 65535 - max IPv4 header (60) - UDP header (8)

	++g_startupCount;
	setLastError(0);
	return 0;
}

int WINAPI WSACleanup() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WSACleanup()\n");
	if (g_startupCount <= 0) {
		setLastError(WSANOTINITIALISED);
		return SOCKET_ERROR;
	}

	--g_startupCount;
	setLastError(0);
	return 0;
}

int WINAPI WSAGetLastError() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WSAGetLastError() -> %d\n", g_lastError);
	return g_lastError;
}

int WINAPI gethostname(LPSTR name, int namelen) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("gethostname(%p, %d)\n", name, namelen);
	if (!requireStarted()) {
		return SOCKET_ERROR;
	}
	if (!name || namelen <= 0) {
		setLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}

	char host[256] = {};
	if (::gethostname(host, sizeof(host) - 1) != 0 || host[0] == '\0') {
		std::strncpy(host, "localhost", sizeof(host) - 1);
	}

	size_t length = std::strlen(host);
	if (static_cast<size_t>(namelen) <= length) {
		setLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}

	std::memcpy(name, host, length + 1);
	setLastError(0);
	return 0;
}

GUEST_PTR WINAPI gethostbyname(LPCSTR name) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("gethostbyname(%s)\n", name ? name : "(null)");
	if (!requireStarted()) {
		return GUEST_NULL;
	}
	setLastError(WSAHOST_NOT_FOUND);
	return GUEST_NULL;
}

int WINAPI select(int nfds, LPVOID readfds, LPVOID writefds, LPVOID exceptfds, const void *timeout) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("select(%d, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout);
	if (!requireStarted()) {
		return SOCKET_ERROR;
	}
	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	setLastError(0);
	return 0;
}

} // namespace ws2

#include "ws2_trampolines.h"

static void *resolveByOrdinal(uint16_t ordinal) {
	// GHS 5.3.22 imports WS2_32.dll with the legacy winsock ordinal table.
	// Keep these mappings tied to observed call sites rather than modern WS2_32 export ordinals.
	switch (ordinal) {
	case 18:
		return (void *)thunk_ws2_select;
	case 52:
		return (void *)thunk_ws2_gethostbyname;
	case 57:
		return (void *)thunk_ws2_gethostname;
	case 115:
		return (void *)thunk_ws2_WSAStartup;
	case 116:
		return (void *)thunk_ws2_WSACleanup;
	}
	return nullptr;
}

extern const wibo::ModuleStub lib_ws2 = {
	(const char *[]){
		"WS2_32",
		nullptr,
	},
	ws2ThunkByName,
	resolveByOrdinal,
};
