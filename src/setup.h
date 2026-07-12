#pragma once

#include "types.h"

#define USER_PRIVILEGE 3

#ifdef __cplusplus
extern "C" {
#endif

bool tebThreadSetup(TEB *teb);
bool tebThreadTeardown(TEB *teb);
void initFpState();

#ifdef __cplusplus
}
#endif
