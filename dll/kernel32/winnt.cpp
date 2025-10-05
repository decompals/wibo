#include "winnt.h"

#include "common.h"

namespace kernel32 {

void WIN_FUNC RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("RtlUnwind(%p, %p, %p, %p)\n", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
	DEBUG_LOG("WARNING: Silently returning from RtlUnwind - exception handlers and clean up code may not be run\n");
}

} // namespace kernel32
