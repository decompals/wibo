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
	PVOID AdditionalSecurityInfo;
};

union CLIENT_CALL_RETURN {
	PVOID Pointer;
	LONG_PTR Simple;
};

namespace rpcrt4 {

RPC_STATUS WINAPI RpcStringBindingComposeW(RPC_WSTR objUuid, RPC_WSTR protSeq, RPC_WSTR networkAddr, RPC_WSTR endpoint,
										   RPC_WSTR options, RPC_WSTR *stringBinding);
RPC_STATUS WINAPI RpcBindingFromStringBindingW(RPC_WSTR stringBinding, RPC_BINDING_HANDLE *binding);
RPC_STATUS WINAPI RpcBindingSetAuthInfoExW(RPC_BINDING_HANDLE binding, RPC_WSTR serverPrincName, ULONG authnLevel,
										   ULONG authnSvc, RPC_AUTH_IDENTITY_HANDLE authIdentity, ULONG authzSvc,
										   RPC_SECURITY_QOS *securityQos);
RPC_STATUS WINAPI RpcBindingFree(RPC_BINDING_HANDLE *binding);
RPC_STATUS WINAPI RpcStringFreeW(RPC_WSTR *string);
CLIENT_CALL_RETURN CDECL_NO_CONV NdrClientCall2(PMIDL_STUB_DESC stubDescriptor, PFORMAT_STRING format, ...);
VOID WINAPI NdrServerCall2(PRPC_MESSAGE message);

} // namespace rpcrt4
