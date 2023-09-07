// Commander X16 Emulator
// Copyright (c) 2023 Florian Deckert
// All rights reserved. License: 2-clause BSD

#include <stdbool.h>

enum REMOTED_CMD { CPU_STOP, CPU_EXECUTE_NEXT, CPU_NEXT, CPU_RUN, CPU_EXIT, CPU_RESTART };

bool remoted_open(char *prg_path);
void remoted_close(void);
enum REMOTED_CMD remoted_getStatus(void);

// provide access too global variable from main
extern SDL_RWops *prg_file;
extern bool       prg_consumed;
