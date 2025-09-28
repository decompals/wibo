#include "common.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>

namespace {

using RPC_STATUS = unsigned long;
using RPC_WSTR = uint16_t *;
using RPC_BINDING_HANDLE = void *;
using RPC_AUTH_IDENTITY_HANDLE = void *;
using LONG_PTR = intptr_t;
using PMIDL_STUB_DESC = void *;
using PFORMAT_STRING = unsigned char *;
using PRPC_MESSAGE = void *;

constexpr RPC_STATUS RPC_S_OK = 0;
constexpr RPC_STATUS RPC_S_INVALID_STRING_BINDING = 1700;
constexpr RPC_STATUS RPC_S_INVALID_BINDING = 1702;
constexpr RPC_STATUS RPC_S_SERVER_UNAVAILABLE = 1722;
constexpr RPC_STATUS RPC_S_INVALID_ARG = 87;
constexpr RPC_STATUS RPC_S_OUT_OF_MEMORY = 14;

struct RPC_SECURITY_QOS {
	unsigned long Version = 0;
	unsigned long Capabilities = 0;
	unsigned long IdentityTracking = 0;
	unsigned long ImpersonationType = 0;
	void *AdditionalSecurityInfo = nullptr;
};

struct BindingComponents {
	std::u16string objectUuid;
	std::u16string protocolSequence;
	std::u16string networkAddress;
	std::u16string endpoint;
	std::u16string options;
};

struct BindingHandleData {
	BindingComponents components;
	std::u16string bindingString;
	std::u16string serverPrincipalName;
	unsigned long authnLevel = 0;
	unsigned long authnService = 0;
	RPC_AUTH_IDENTITY_HANDLE authIdentity = nullptr;
	unsigned long authzService = 0;
	bool hasAuthInfo = false;
	bool hasSecurityQos = false;
	RPC_SECURITY_QOS securityQos = {};
	bool serverReachable = false;
};

union CLIENT_CALL_RETURN {
	void *Pointer;
	LONG_PTR Simple;
};

std::unordered_map<RPC_WSTR, BindingComponents> g_stringBindings;
std::unordered_map<RPC_BINDING_HANDLE, std::unique_ptr<BindingHandleData>> g_bindingHandles;

std::u16string toU16(RPC_WSTR str) {
	if (!str) {
		return {};
	}
	auto *ptr = reinterpret_cast<const char16_t *>(str);
	size_t length = 0;
	while (ptr[length] != 0) {
		++length;
	}
	return std::u16string(ptr, ptr + length);
}

std::string narrow(const std::u16string &value) {
	std::string out;
	out.reserve(value.size());
	for (char16_t ch : value) {
		if (ch <= 0x7F) {
			out.push_back(static_cast<char>(ch));
		} else {
			out.push_back('?');
		}
	}
	return out;
}

std::u16string composeString(const BindingComponents &components) {
	std::u16string result;
	if (!components.objectUuid.empty()) {
		result += components.objectUuid;
		result += u"@";
	}
	if (!components.protocolSequence.empty()) {
		result += components.protocolSequence;
	}
	if (!components.networkAddress.empty()) {
		if (!components.protocolSequence.empty()) {
			result += u":";
		}
		result += components.networkAddress;
	}
	if (!components.endpoint.empty()) {
		result += u"[";
		result += components.endpoint;
		result += u"]";
	}
	if (!components.options.empty()) {
		result += u"{";
		result += components.options;
		result += u"}";
	}
	return result;
}

BindingHandleData *getBinding(RPC_BINDING_HANDLE handle) {
	auto it = g_bindingHandles.find(handle);
	if (it == g_bindingHandles.end()) {
		return nullptr;
	}
	return it->second.get();
}

} // namespace

extern "C" {

RPC_STATUS WIN_FUNC RpcStringBindingComposeW(RPC_WSTR objUuid, RPC_WSTR protSeq, RPC_WSTR networkAddr,
											 RPC_WSTR endpoint, RPC_WSTR options, RPC_WSTR *stringBinding) {
	BindingComponents components;
	components.objectUuid = toU16(objUuid);
	components.protocolSequence = toU16(protSeq);
	components.networkAddress = toU16(networkAddr);
	components.endpoint = toU16(endpoint);
	components.options = toU16(options);

	std::u16string encoded = composeString(components);
	DEBUG_LOG("RpcStringBindingComposeW -> %s\n", narrow(encoded).c_str());

	if (stringBinding) {
		size_t length = encoded.size();
		auto *buffer = static_cast<char16_t *>(std::malloc((length + 1) * sizeof(char16_t)));
		if (!buffer) {
			return RPC_S_OUT_OF_MEMORY;
		}
		if (length > 0) {
			std::memcpy(buffer, encoded.data(), length * sizeof(char16_t));
		}
		buffer[length] = 0;
		RPC_WSTR result = reinterpret_cast<RPC_WSTR>(buffer);
		g_stringBindings[result] = components;
		*stringBinding = result;
	}

	return RPC_S_OK;
}

RPC_STATUS WIN_FUNC RpcBindingFromStringBindingW(RPC_WSTR stringBinding, RPC_BINDING_HANDLE *binding) {
	if (!binding) {
		return RPC_S_INVALID_ARG;
	}
	*binding = nullptr;
	if (!stringBinding) {
		return RPC_S_INVALID_STRING_BINDING;
	}
	auto it = g_stringBindings.find(stringBinding);
	if (it == g_stringBindings.end()) {
		return RPC_S_INVALID_STRING_BINDING;
	}
	auto handleData = std::make_unique<BindingHandleData>();
	handleData->components = it->second;
	handleData->bindingString = composeString(handleData->components);
	handleData->serverReachable = false;
	RPC_BINDING_HANDLE handle = reinterpret_cast<RPC_BINDING_HANDLE>(handleData.get());
	g_bindingHandles.emplace(handle, std::move(handleData));
	*binding = handle;
	DEBUG_LOG("RpcBindingFromStringBindingW(handle=%p)\n", handle);
	return RPC_S_OK;
}

RPC_STATUS WIN_FUNC RpcBindingSetAuthInfoExW(RPC_BINDING_HANDLE binding, RPC_WSTR serverPrincName,
											 unsigned long authnLevel, unsigned long authnSvc,
											 RPC_AUTH_IDENTITY_HANDLE authIdentity, unsigned long authzSvc,
											 RPC_SECURITY_QOS *securityQos) {
	BindingHandleData *data = getBinding(binding);
	if (!data) {
		return RPC_S_INVALID_BINDING;
	}
	data->serverPrincipalName = toU16(serverPrincName);
	data->authnLevel = authnLevel;
	data->authnService = authnSvc;
	data->authIdentity = authIdentity;
	data->authzService = authzSvc;
	data->hasAuthInfo = true;
	if (securityQos) {
		data->securityQos = *securityQos;
		data->hasSecurityQos = true;
	} else {
		data->hasSecurityQos = false;
	}
	DEBUG_LOG("RpcBindingSetAuthInfoExW(handle=%p, authnSvc=%lu, authnLevel=%lu)\n", binding, authnSvc, authnLevel);
	return RPC_S_OK;
}

RPC_STATUS WIN_FUNC RpcBindingFree(RPC_BINDING_HANDLE *binding) {
	if (!binding) {
		return RPC_S_INVALID_ARG;
	}
	RPC_BINDING_HANDLE handle = *binding;
	if (!handle) {
		return RPC_S_INVALID_BINDING;
	}
	auto it = g_bindingHandles.find(handle);
	if (it == g_bindingHandles.end()) {
		return RPC_S_INVALID_BINDING;
	}
	g_bindingHandles.erase(it);
	*binding = nullptr;
	DEBUG_LOG("RpcBindingFree\n");
	return RPC_S_OK;
}

RPC_STATUS WIN_FUNC RpcStringFreeW(RPC_WSTR *string) {
	if (!string) {
		return RPC_S_INVALID_ARG;
	}
	RPC_WSTR value = *string;
	if (!value) {
		return RPC_S_OK;
	}
	auto it = g_stringBindings.find(value);
	if (it != g_stringBindings.end()) {
		g_stringBindings.erase(it);
	}
	std::free(reinterpret_cast<void *>(value));
	*string = nullptr;
	return RPC_S_OK;
}

CLIENT_CALL_RETURN __attribute__((force_align_arg_pointer, callee_pop_aggregate_return(0), cdecl))
NdrClientCall2(PMIDL_STUB_DESC stubDescriptor, PFORMAT_STRING format, ...) {
	DEBUG_LOG("STUB: NdrClientCall2 stubDescriptor=%p format=%p\n", stubDescriptor, format);
	CLIENT_CALL_RETURN result = {};
	result.Simple = RPC_S_SERVER_UNAVAILABLE;
	DEBUG_LOG("NdrClientCall2 returning RPC_S_SERVER_UNAVAILABLE\n");
	return result;
}

void WIN_FUNC NdrServerCall2(PRPC_MESSAGE message) { DEBUG_LOG("STUB: NdrServerCall2 message=%p\n", message); }

} // extern "C"

namespace {

void *resolveByName(const char *name) {
	if (std::strcmp(name, "RpcStringBindingComposeW") == 0)
		return (void *)RpcStringBindingComposeW;
	if (std::strcmp(name, "RpcBindingFromStringBindingW") == 0)
		return (void *)RpcBindingFromStringBindingW;
	if (std::strcmp(name, "RpcStringFreeW") == 0)
		return (void *)RpcStringFreeW;
	if (std::strcmp(name, "RpcBindingFree") == 0)
		return (void *)RpcBindingFree;
	if (std::strcmp(name, "RpcBindingSetAuthInfoExW") == 0)
		return (void *)RpcBindingSetAuthInfoExW;
	if (std::strcmp(name, "NdrClientCall2") == 0)
		return (void *)NdrClientCall2;
	if (std::strcmp(name, "NdrServerCall2") == 0)
		return (void *)NdrServerCall2;
	return nullptr;
}

} // namespace

wibo::Module lib_rpcrt4 = {
	(const char *[]){"rpcrt4", "rpcrt4.dll", nullptr},
	resolveByName,
	nullptr,
};
