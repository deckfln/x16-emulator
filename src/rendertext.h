
#ifndef _RENDERTEXT_H
#define _RENDERTEXT_H

#ifdef _MSC_VER
#	include <SDL2/SDL.h>
#else
#	include <SDL.h>
#endif

#define CHAR_SCALE 		(1)										// character pixel size.

extern int xPos;
extern int yPos;

void DEBUGInitChars(SDL_Renderer *renderer);
void DEBUGWrite(SDL_Renderer *renderer, int x, int y, int ch, SDL_Color colour);
void DEBUGString(SDL_Renderer *renderer, int x, int y, char *s, SDL_Color colour);
char *ltrim(char *s);

#endif
