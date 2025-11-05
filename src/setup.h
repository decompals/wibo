#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __x86_64__
int x86_64_thread_setup(int entry_number, void *teb);
#endif

#ifdef __cplusplus
}
#endif
