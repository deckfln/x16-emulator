// All rights reserved. License: 2-clause BSD

#ifdef _MSC_VER
#	include <SDL2/SDL.h>
#	include <SDL2/SDL_syswm.h>
#else
#	include <SDL.h>
#	include <SDL_syswm.h>
#endif


#include <windows.h>
#include <dwmapi.h>

void video_win32_set_rounded_corners(SDL_Window *window)
{
	SDL_SysWMinfo wmInfo;
	SDL_VERSION(&wmInfo.version);
	SDL_GetWindowWMInfo(window, &wmInfo);

	// TODO : cannot find DWM_WINDOW_CORNER_PREFERENCE on my dwmapi.h
	#ifdef false
	HWND hwnd = wmInfo.info.win.window;
	DWM_WINDOW_CORNER_PREFERENCE preference = DWMWCP_ROUNDSMALL;
	DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &preference, sizeof(preference));
	#endif
}
