#pragma once

#include "types.h"

using RPC_STATUS = ULONG;
using RPC_WSTR = LPWSTR;
using RPC_BINDING_HANDLE = PVOID;
using RPC_AUTH_IDENTITY_HANDLE = PVOID;
using PMIDL_STUB_DESC = PVOID;
using PFORMAT_STRING = PUCHAR;
using PRPC_MESSAGE = PVOID;

struct RPC_SECURITY_QOS {
	ULONG Version;
	ULONG Capabilities;
	ULONG IdentityTracking;
	ULONG ImpersonationType;
	GUEST_PTR AdditionalSecurityInfo;
};

union CLIENT_CALL_RETURN {
	GUEST_PTR Pointer;
	LONG_PTR Simple;
};

namespace rpcrt4 {

RPC_STATUS WINAPI RpcStringBindingComposeW(RPC_WSTR objUuid, RPC_WSTR protSeq, RPC_WSTR networkAddr, RPC_WSTR endpoint,
										   RPC_WSTR options, GUEST_PTR *stringBinding);
RPC_STATUS WINAPI RpcBindingFromStringBindingW(RPC_WSTR stringBinding, GUEST_PTR *binding);
RPC_STATUS WINAPI RpcBindingSetAuthInfoExW(RPC_BINDING_HANDLE binding, RPC_WSTR serverPrincName, ULONG authnLevel,
										   ULONG authnSvc, RPC_AUTH_IDENTITY_HANDLE authIdentity, ULONG authzSvc,
										   RPC_SECURITY_QOS *securityQos);
RPC_STATUS WINAPI RpcBindingFree(GUEST_PTR *binding);
RPC_STATUS WINAPI RpcStringFreeW(GUEST_PTR *string);
#ifndef __x86_64__ // TODO
CLIENT_CALL_RETURN CDECL_NO_CONV NdrClientCall2(PMIDL_STUB_DESC stubDescriptor, PFORMAT_STRING format, ...);
#endif
VOID WINAPI NdrServerCall2(PRPC_MESSAGE message);

} // namespace rpcrt4
