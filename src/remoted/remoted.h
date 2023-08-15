// Commander X16 Emulator
// Copyright (c) 2023 Florian Deckert
// All rights reserved. License: 2-clause BSD

#pragma once

#include <stdbool.h>

bool remoted_open(void);
void remoted_close(void);
void remoted_getcommand(void);
