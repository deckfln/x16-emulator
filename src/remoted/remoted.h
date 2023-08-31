// Commander X16 Emulator
// Copyright (c) 2023 Florian Deckert
// All rights reserved. License: 2-clause BSD

#pragma once

#include <stdbool.h>

enum REMOTED_CMD {
	CPU_STOP,
	CPU_EXECUTE_NEXT,
	CPU_NEXT,
	CPU_RUN,
	CPU_EXIT
};


bool remoted_open(void);
void remoted_close(void);
enum REMOTED_CMD remoted_getStatus(void);
