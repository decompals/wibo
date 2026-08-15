#pragma once

#include "types.h"

struct WSADATA {
	WORD wVersion;
	WORD wHighVersion;
	CHAR szDescription[257];
	CHAR szSystemStatus[129];
	WORD iMaxSockets;
	WORD iMaxUdpDg;
	GUEST_PTR lpVendorInfo;
};

namespace ws2 {

int WINAPI WSAStartup(WORD wVersionRequired, WSADATA *lpWSAData);
int WINAPI WSACleanup();
int WINAPI WSAGetLastError();
int WINAPI gethostname(LPSTR name, int namelen);
GUEST_PTR WINAPI gethostbyname(LPCSTR name);
int WINAPI select(int nfds, LPVOID readfds, LPVOID writefds, LPVOID exceptfds, const void *timeout);

} // namespace ws2
