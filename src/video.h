// Commander X16 Emulator
// Copyright (c) 2019 Michael Steil
// All rights reserved. License: 2-clause BSD

#ifndef _VIDEO_H_
#define _VIDEO_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifdef _MSC_VER
#include <SDL2/SDL.h>
#else
#include <SDL.h>
#endif
#include "glue.h"

bool video_init(int window_scale, float screen_x_scale, char *quality, bool fullscreen, float opacity);
void video_reset(void);
bool video_step(float mhz, float steps, bool midline);
bool video_update(void);
void video_end(void);
bool video_get_irq_out(void);
void video_save(SDL_RWops *f);
uint8_t video_read(uint8_t reg, bool debugOn);
void video_write(uint8_t reg, uint8_t value);
void video_update_title(const char* window_title);

uint8_t via1_read(uint8_t reg, bool debug);
void via1_write(uint8_t reg, uint8_t value);

// For debugging purposes only:
uint8_t video_space_read(uint32_t address);
void video_space_write(uint32_t address, uint8_t value);

bool video_is_tilemap_address(int addr);
bool video_is_tiledata_address(int addr);
bool video_is_special_address(int addr);

uint32_t video_get_address(uint8_t sel);

struct video_sprite_properties {
	int8_t  sprite_zdepth;
	uint8_t sprite_collision_mask;

	int16_t sprite_x;
	int16_t sprite_y;
	uint8_t sprite_width_log2;
	uint8_t sprite_height_log2;
	uint8_t sprite_width;
	uint8_t sprite_height;

	bool hflip;
	bool vflip;

	uint8_t  color_mode;
	uint32_t sprite_address;

	uint16_t palette_offset;
};

// code source https://github.com/indigodarkwolf/box16
struct video_sprite_properties *video_get_sprite_properties(uint8_t spriteID);
const uint32_t *vera_video_get_palette_argb32(void);

#endif
