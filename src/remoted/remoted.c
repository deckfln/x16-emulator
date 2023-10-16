#include "../../src/timing.h"

#ifdef _MSC_VER
#	include <winsock2.h>
#	include <SDL2/SDL.h>
#	include <process.h>
#else
#	include <signal.h>
#	include <SDL.h>
#	include <sys/types.h>
#	include <unistd.h>
#	include <stdio.h>
#	include <string.h>
#	define _getpid(a) getpid(a)
char *_strdup(const char *s) {
    size_t size = strlen(s) + 1;
    char *p = malloc(size);
    if (p) {
        memcpy(p, s, size);
    }
    return p;
}
#endif
#include <microhttpd.h>
#include <png.h>
#include <cjson/cJSON.h>

#include "remoted.h"

#include "../video.h"
#include "../memory.h"
#include "../debugger.h"
#include "../glue.h"

//-----------------------------------------------------------
//   private functions
//-----------------------------------------------------------

static int RD_pid = -1;		// current process ID
static char *RD_prg_path = NULL;	// full path of the currently debugged PRG
static enum REMOTED_CMD myStatus = CPU_RUN;

static struct MHD_Daemon *daemon = NULL;

static char *ok = "{\"status\" : \"ok\"}";

static char json[8192];
static uint8_t dump[1024];
static char tmp[256] = {0};
static uint16_t _start   = 0;	// target to restart the PRG

#ifndef _MSC_VER
#	define strtok_s(a, b, c) strtok(a, b)
#	define strcat_s(a, b, c) strcat(a,c)
#endif

/**
 *
 */
struct MHD_Response *
remoted_error(struct MHD_Connection *connection, const char *page)
{
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
	MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
	MHD_queue_response(connection, MHD_HTTP_OK, response);
	return response;
}

/**
 *
 */
struct MHD_Response *
remoted_ok(struct MHD_Connection *connection)
{
	return remoted_error(connection, ok);
}

/**
 * send a json as response
 */
struct MHD_Response *
remoted_json(struct MHD_Connection *connection, cJSON *answer)
{
	char *string = cJSON_Print(answer);
	cJSON_Delete(answer);
#ifdef _MSC_VER
	strncpy_s(json, sizeof(json), string, sizeof(json));
#else
	strncpy(json, string, sizeof(json));
#endif
	free(string);

	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
	MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
	MHD_queue_response(connection, MHD_HTTP_OK, response);

	return response;
}

/********************************************************************
 *		manage memory & vram Watch breakpoints
 ********************************************************************/

#define MAX_WATCHES 128

enum WATCH_STATUS {
	OFF,
	VALUE_CHANGED,
	EXACT_VALUE,
	VRAM = 128
};

struct myWatch {
	uint8_t  status;
	uint8_t  len; // 8 bits, 16 bits, 24 bits, 32 bits
	uint16_t addr;
	uint8_t bank;
	uint32_t prev_value; // value at previous instruction
	uint32_t watchFor;   // value to monitor
};

static struct myWatch watches[MAX_WATCHES];

/**
 * read memory
 */
static uint32_t
read_memory(uint16_t len, uint16_t address, uint8_t bank)
{
	switch (len) {
		case 1:
			return real_read6502(address, true, bank);
		case 2:
			return (real_read6502(address, true, bank) << 8) | real_read6502(address + 1, true, bank);
		case 4:
			return (real_read6502(address, true, bank) << 24) |
			       (real_read6502(address + 1, true, bank) << 16) |
			       (real_read6502(address + 2, true, bank) << 8) |
			       real_read6502(address + 3, true, bank);
		default:
#ifdef _MSC_VER
			__debugbreak();
#else
			raise(SIGTRAP);
#endif
	}

	return 0;
}

 /**
 * Set memory WATCH breakpoint
 * /watch/bank/memory/len/value
 */
static struct MHD_Response *
remoted_watch_toggle(uint8_t type, char *token, struct MHD_Connection *connection, char **next_token)
{
	static char *nok = "{\"status\" : \"error\", \"message\":\"no available breakpoint\"}";

	// change a watch
	uint8_t status = OFF;
	uint8_t length = 0;
	uint8_t value  = 0;

	uint8_t bank = (uint8_t)atoi(token);
	char   *addr = strtok_s(NULL, "/", next_token);
	if (token != NULL) {
		uint16_t address = 0;
		if (addr[0] == '0' && addr[2] == 'x') {
			address = (uint16_t)strtol(addr + 2, NULL, 16);
		} else {
			address = (uint16_t)atoi(addr);
		}

		char *slength = strtok_s(NULL, "/", next_token);
		if (slength != NULL) {
			length = atoi(slength);

			status       = VALUE_CHANGED;
			char *svalue = strtok_s(NULL, "/", next_token);
			if (svalue != NULL) {
				value  = atoi(svalue);
				status = EXACT_VALUE;
			}
		}

		char *json = nok;

		// find first available watch
		// and check if the watch is already set
		int index           = -1;
		int first_available = -1;
		for (int i = 0; i < MAX_WATCHES; i++) {
			if (watches[i].status == OFF && first_available < 0) {
				first_available = i;
			} else if (watches[i].addr == address && watches[i].bank == bank) {
				index = i;
				break;
			}
		}

		if (index >= 0) {
			// the watch already exists
			switch (status) {
				case EXACT_VALUE:
					watches[index].watchFor = value;
					watches[index].len      = length;
					break;
				case VALUE_CHANGED:
					watches[index].len        = length;
					if (type == VRAM) {
						uint32_t vram_addr = (bank << 16) | address;
						watches[index].prev_value = video_space_read(vram_addr);
					}
					else {
						watches[index].prev_value = read_memory(length, address, bank);
					}
					break;
				default:
					// remove the watch
					watches[index].status = OFF;
			}
			json = ok;
		} else if (first_available >= 0) {
			// create a new watch
			watches[first_available].addr       = address;
			watches[first_available].bank       = bank;
			watches[first_available].len        = length;

			if (type == VRAM) {
				uint32_t vram_addr        = (bank << 16) | address;
				watches[first_available].prev_value = video_space_read(vram_addr);
			} else {
				watches[first_available].prev_value = read_memory(length, address, bank);
			}

			if (status == EXACT_VALUE) {
				watches[first_available].status   = EXACT_VALUE | type;
				watches[first_available].watchFor = value;
			} else {
				watches[first_available].status = VALUE_CHANGED | type;
			}
			json = ok;
		} else {
			json = nok; // no available slot
		}

		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		MHD_queue_response(connection, MHD_HTTP_OK, response);
		return response;
	}

	const char *page = "missing bank for watch";
	return remoted_error(connection, page);
}

/**
 * init breakpoints
 */
static void
initWatches(void)
{
	for (int i = 0; i < MAX_WATCHES; i++) {
		watches[i].status = OFF;
	}
}

/**
 * did we hit a breakpoint ?
 */
static bool
hitWatch(void)
{
	// check dev defined breakpoints
	for (int i = 0; i < MAX_WATCHES; i++) {
		if (watches[i].status == OFF) {
			continue;
		}

		uint16_t a = watches[i].addr;
		uint8_t  b = watches[i].bank;
		uint32_t v = 0;

		if ((watches[i].status & 0x80) == VRAM) {
			uint32_t vram_addr = (b << 16) | a;
			v                  = video_space_read(vram_addr);
		} else {
			v = read_memory(watches[i].len, a, b);
		}

		switch (watches[i].status & 0x7f) {
			case EXACT_VALUE:
				return v == watches[i].watchFor;
			case VALUE_CHANGED: {
				bool t = v != watches[i].prev_value;
				if (t) {
					watches[i].prev_value = v;
				}
				return t;
			}
		}
	}
	return false;
}

/**
 * provide list of watches
 */
static struct MHD_Response *
remoted_watch_list(struct MHD_Connection *connection, char **next_token)
{
	// provide a list of watches
	json[0] = '[';
	json[1] = 0;

	// return a list of breakpoints
	bool first = true;
	for (int i = 0; i < MAX_WATCHES; i++) {
		if ((watches[i].status & 0x7f) != OFF) {
			if (!first) {
				strcat_s(json, sizeof(json), ",");
			}
			snprintf(tmp, sizeof(tmp), "{\"status\":%d,\"addr\":%d, \"bank\":%d, \"len\":%d}", watches[i].status, watches[i].addr, watches[i].bank, watches[i].len);
			strcat_s(json, sizeof(json), tmp);
			first = false;
		}
	}
	strcat_s(json, sizeof(json), "]");

	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
	MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
	MHD_queue_response(connection, MHD_HTTP_OK, response);
	return response;
}

/**
 * Set memory WATCH breakpoint
 * /watch/bank/memory/len/value
 */
static struct MHD_Response *
remoted_watch(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL) {
		return remoted_watch_toggle(0, token, connection, next_token);
	} else {
		return remoted_watch_list(connection, next_token);
	}
	const char *page = "incorect breakpoint command provided";
	return remoted_error(connection, page);
}

/********************************************************************
 *		manage memory Watch breakpoints
 ********************************************************************/

/**
 *
 */
/* structure to store PNG image bytes */
struct png_mem_encode {
	char  *buffer;
	size_t size;
};

/* Pixels in this bitmap structure are stored as BGR. */
typedef struct _RGBPixel {
	uint8_t blue;
	uint8_t green;
	uint8_t red;
} RGBPixel;

/* Structure for containing decompressed bitmaps. */
typedef struct _RGBBitmap {
	RGBPixel *pixels;
	size_t    width;
	size_t    height;
	size_t    bytewidth;
	uint8_t   bytes_per_pixel;
} RGBBitmap;

/* Returns pixel of bitmap at given point. */
#define RGBPixelAtPoint(image, x, y) \
	*(((image)->pixels) + (((image)->bytewidth * (y)) + ((x) * (image)->bytes_per_pixel)))

// write 1 row of PNG in memory
void static my_png_write_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
	/* with libpng15 next line causes pointer deference error; use libpng12 */
	struct png_mem_encode *p     = (struct png_mem_encode *)png_get_io_ptr(png_ptr); /* was png_ptr->io_ptr */
	size_t             nsize = p->size + length;

	/* allocate or grow buffer */
	if (p->buffer)
		p->buffer = realloc(p->buffer, nsize);
	else
		p->buffer = malloc(nsize);

	if (!p->buffer)
		png_error(png_ptr, "Write Error");

	/* copy new bytes to end of buffer */
	memcpy(p->buffer + p->size, data, length);
	p->size += length;
}

static bool
sprite_to_png(struct png_mem_encode *target, uint32_t *bitmap, uint8_t width, uint8_t height)
{
	png_structp png_ptr  = NULL;
	png_infop   info_ptr = NULL;
	size_t      x, y;
	png_uint_32 bytes_per_row;

	/* Initialize the write struct. */
	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (png_ptr == NULL) {
		return false;
	}

	/* Initialize the info struct. */
	info_ptr = png_create_info_struct(png_ptr);
	if (info_ptr == NULL) {
		png_destroy_write_struct(&png_ptr, NULL);
		return false;
	}

	/* Set up error handling. */
	if (setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		return false;
	}

	/* Set image attributes. */
	png_set_IHDR(png_ptr, info_ptr, width, height, 8, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    /* Initialize rows of PNG. */
	bytes_per_row = width * 4;
	png_byte **row_pointers = (png_byte **)png_malloc(png_ptr, height * sizeof(png_byte *));
	uint8_t   *imgBfr       = (uint8_t *)calloc(1, height * bytes_per_row * sizeof(uint8_t));

	for (y = 0; y < height; ++y) {
		row_pointers[y] = (png_byte *)(imgBfr + y * bytes_per_row);
		uint8_t *row = (uint8_t *)row_pointers[y];
		uint32_t *color = bitmap + (width * y);
		for (x = 0; x < width; ++x) {
			*(row++) = (*color & 0x000000ff);           // A
			*(row++) = (*color & 0xff000000) >> 24;     // R
			*(row++) = (*color & 0x00ff0000) >> 16;		// G
			*(row++) = (*color & 0x0000ff00) >> 8;		// B
			color++;
		}
	}
	/* Actually write the image data. */
	png_set_swap_alpha(png_ptr);
	png_set_rows(png_ptr, info_ptr, row_pointers);
	png_set_write_fn(png_ptr, target, my_png_write_data, NULL);
	png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

	/* Cleanup. */
	free(imgBfr);

	/* Finish writing. */
	png_destroy_write_struct(&png_ptr, &info_ptr);

	return true;
}

/**
 * display sprites
 */
static struct MHD_Response *
remoted_sprite(struct MHD_Connection* connection, char** next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL) {
		int32_t spriteID = atoi(token);

		if (spriteID >= 0 && spriteID < 128) {

			const uint32_t *palette_argb = vera_video_get_palette_argb32();
			static uint32_t palette[256];
			// skip color 0, it will always be transparent
			for (int i = 1; i < 256; i++) {
				palette[i] = (palette_argb[i] << 8) | 0xFF;
			}
			static uint32_t img_argb[64 * 64];

			char page[1024];
			struct video_sprite_properties *prop = video_get_sprite_properties(spriteID);
			const uint8_t width  = prop->sprite_width;
			const uint8_t height = prop->sprite_height;
			const bool hflip  = prop->hflip;
			const bool vflip  = prop->vflip;


			uint32_t bitmap = prop->sprite_address;
			uint32_t *ptr = img_argb;
			uint8_t  val;

			for (uint8_t y = 0; y < height; y++) {
				int dst     = vflip ? (height - y - 1) * width : y * width;
				int dst_add = 1;
				if (hflip) {
					dst += width - 1;
					dst_add = -1;
				}
				if (prop->color_mode) {
					for (int j = 0; j < width; j++) {
						val      = video_space_read(bitmap++);
						ptr[dst] = palette[val];
						dst += dst_add;
					}
				} else {
					for (int j = 0; j < width; j++) {
						val = video_space_read(bitmap++);
						;
						if (val) {
							val += prop->palette_offset;
						}
						ptr[dst] = palette[val];
						dst += dst_add;
					}
				}
			}
			struct png_mem_encode target = {NULL, 0};
			sprite_to_png(&target, img_argb, width, height);

			snprintf(page, sizeof(page), "spriteID %d", spriteID);
			struct MHD_Response *response = MHD_create_response_from_buffer(target.size, target.buffer, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "image/png");
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			MHD_queue_response(connection, MHD_HTTP_OK, response);

			return response;
		} else {
			const char *page = "incorrect spriteID";
			return remoted_error(connection, page);
		}
	}
	const char *page = "no spriteID provided";
	return remoted_error(connection, page);
}

/**
 * Dump VERA memory
 */
/**
 * Display VERA information
 */
static struct MHD_Response *
remoted_vera_dump(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);
	static uint8_t *dumpster = NULL;
	static uint32_t dumpster_l = 0;

	if (token != NULL) {
		uint32_t start = (uint32_t)atoi(token);

		char  *length = strtok_s(NULL, "/", next_token);
		size_t l      = 256;
		if (length != NULL) {
			l = (size_t)atoi(length);
		}

		if (dumpster == NULL) {
			dumpster_l = l*2;
			dumpster   = (uint8_t *)malloc(dumpster_l);
		} else if (dumpster_l < l) {
			free(dumpster);
			dumpster_l = l * 2;
			dumpster   = (uint8_t *)malloc(dumpster_l);
		}
		uint8_t *p     = dumpster;

		for (int i = 0,j=0; i < l; i++, j+=2) {
			uint32_t addr = (start + i) & 0x1FFFF;
			uint8_t  byte = video_space_read(addr);
			uint8_t  type = 0;

			if (video_is_tilemap_address(addr)) {
				type = 1; // vram_tilemap;
			} else if (video_is_tiledata_address(addr)) {
				type = 2; // vram_tiledata;
			} else if (video_is_special_address(addr)) {
				type = 3; // vram_special;
			} else {
				type = 4; // vram_other;
			}

			dumpster[j] = type;
			dumpster[j+1] = byte;

			if (j > dumpster_l) {
				__debugbreak();
			}
		}

		struct MHD_Response *response = MHD_create_response_from_buffer(l*2, dumpster, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/octet-stream");
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		MHD_queue_response(connection, MHD_HTTP_OK, response);
		return response;
	}

	const char *page = "missing vera dump address ";
	return remoted_error(connection, page);
}

/**
 *
 */
static struct MHD_Response *
remoted_vera_watch(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL) { 
		return remoted_watch_toggle(VRAM, token, connection, next_token);
	} else {
		return remoted_watch_list(connection, next_token);
	}
	const char *page = "incorect breakpoint command provided";
	return remoted_error(connection, page);
}

/**
 * Display VERA information
 */
static struct MHD_Response *
remoted_vera(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL && strcmp(token, "sprite") == 0) {
		return remoted_sprite(connection, next_token);
	}
	else if (token != NULL && strcmp(token, "dump") == 0) {
		return remoted_vera_dump(connection, next_token);
	}

	const char *page = "incorect vera command provided";
	return remoted_error(connection, page);
}

/********************************************************************
 *		manage memory
 ********************************************************************/

static int
getCurrentBank(int pc)
{
	int bank = 0;
	if (pc >= 0xA000) {
		bank = pc < 0xC000 ? memory_get_ram_bank() : memory_get_rom_bank();
	}
	return bank;
}

/**
 * Display MEMORY information /dump/bank/address/len
 */
static struct MHD_Response *
remoted_dump(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	int len = 256;

	if (token != NULL) {
		uint8_t bank = (uint8_t)atoi(token);
		char    *addr = strtok_s(NULL, "/", next_token);
		if (token != NULL) {
			uint16_t address;
			if (addr[0] == '0' && addr[1] == 'x')
				address = (uint16_t)strtol(addr, NULL, 16);
			else
				address = (uint16_t)atoi(addr);

			char *slength = strtok_s(NULL, "/", next_token);
			if (slength != NULL) {
				len = atoi(slength);
			}

			for (int i = 0; i < len; i++) {
				dump[i] = real_read6502(address++, true, bank);
			}
			struct MHD_Response *response = MHD_create_response_from_buffer(len, dump, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/octet-stream");
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			MHD_queue_response(connection, MHD_HTTP_OK, response);
			return response;
		}
	}

	const char *page = "incorect dump command provided";
	return remoted_error(connection, page);
}

/********************************************************************
 *		manage CPU breakpoints
 ********************************************************************/

#define MAX_BREAKPOINTS 128

struct myBreakpoint {
	bool active;
	uint16_t pc;
	uint16_t bank;
};
static struct myBreakpoint breakpoints[MAX_BREAKPOINTS];
static struct myBreakpoint stepOver = {false, 0, 0};

/**
 * init breakpoints
 */
static void
initBreakpoints(void)
{
	for (int i = 0; i < MAX_BREAKPOINTS; i++) {
		breakpoints[i].active = false;
	}
}

/**
 * did we hit a breakpoint ?
 */
static bool
hitBreakpoint(uint16_t pc, uint8_t bank)
{
	// check dev defined breakpoints
	for (int i = 0; i < MAX_BREAKPOINTS; i++) {
		if (breakpoints[i].active && breakpoints[i].bank == bank && breakpoints[i].pc == pc) {
			return true;
		}
	}

	// check the stepOver
	if (stepOver.active && stepOver.bank == bank && stepOver.pc == pc) {
		stepOver.active = false;
		return true;
	}

	return false;
}

/**
 * Set CPU breakpoint
 * /breakpoint
 * /breakpoint/bank/address
 */
static struct MHD_Response *
remoted_breakpoint(struct MHD_Connection *connection, char **next_token)
{
	static char *nok = "{\"status\" : \"error\", \"message\":\"no available breakpoint\"}";

	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL) {
		uint8_t bank = (uint8_t)atoi(token);
		char   *addr = strtok_s(NULL, "/", next_token);
		if (token != NULL) {
			uint16_t address = 0;
			if (addr[0] == '0' && addr[2] == 'x') {
				address = (uint16_t)strtol(addr + 2, NULL, 16);
			} else {
				address = (uint16_t)atoi(addr);
			}
			char *json = nok;

			// find first available breakpoint
			// and check if the breakpoint is already set
			int first_available = -1;
			for (int i = 0; i < MAX_BREAKPOINTS; i++) {
				if (breakpoints[i].active == false && first_available < 0) {
					first_available = i;
				} else if (breakpoints[i].pc == address && breakpoints[i].bank == bank) {
					breakpoints[i].active = false;
					json                  = ok;
					break;
				}
			}

			if (json == nok && first_available >= 0) {
				breakpoints[first_available].active = true;
				breakpoints[first_available].pc     = address;
				breakpoints[first_available].bank   = bank;
				json                                = ok;
			}

			struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			MHD_queue_response(connection, MHD_HTTP_OK, response);
			return response;
		}
	} else {
		json[0] = '[';
		json[1] = 0;

		// return a list of breakpoints
		bool first = true;
		for (int i = 0; i < MAX_BREAKPOINTS; i++) {
			if (breakpoints[i].active) {
				if (!first) {
					strcat_s(json, sizeof(json), ",");
				}
				snprintf(tmp, sizeof(tmp), "{\"addr\":%d, \"bank\":%d}", breakpoints[i].pc, breakpoints[i].bank);
				strcat_s(json, sizeof(json), tmp);
				first = false;
			}
		}
		strcat_s(json, sizeof(json), "]");

		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		MHD_queue_response(connection, MHD_HTTP_OK, response);
		return response;
	}
	const char *page = "incorect breakpoint command provided";
	return remoted_error(connection, page);
}

/********************************************************************
 *		step by step /debug/
 * /debug/stepinto
 * /debug/stepover
 * /debug/stepout
 * /debug/continue
 ********************************************************************/

static struct MHD_Response *
remoted_debug(struct MHD_Connection *connection, char **next_token)
{
	char *token = strtok_s(NULL, "/", next_token);

	if (token != NULL) {
		if (strcmp(token, "stepinto") == 0) {
			myStatus = CPU_EXECUTE_NEXT;
		}
		else if (strcmp(token, "continue") == 0) {
			myStatus = CPU_RUN;
		} else if (strcmp(token, "stepover") == 0) {
			int bank   = getCurrentBank(pc);
			int opcode = real_read6502(pc, true, bank); // What opcode is it ?
			if (opcode == 0x20) {                            // Is it JSR ?
				stepOver.pc   = pc + 3;                // Then break 3 on.
				stepOver.bank = getCurrentBank(pc);
				stepOver.active = true;
				timing_init();
				myStatus = CPU_RUN;
			} else {
				myStatus = CPU_EXECUTE_NEXT;
			}
		}
		else if (strcmp(token, "stepout") == 0) {
			// extract PC from the stack
#define BASE_STACK 0x100
			uint16_t rts = read6502(BASE_STACK + ((sp + 1) & 0xFF)) | ((uint16_t)read6502(BASE_STACK + ((sp + 2) & 0xFF)) << 8);
			uint16_t nexti = rts + 1;
			stepOver.pc     = nexti;
			stepOver.bank   = getCurrentBank(pc);
			stepOver.active = true;
			timing_init();
			myStatus = CPU_RUN;
		}

		return remoted_ok(connection);
	}

	const char *page = "incorect debug command provided";
	return remoted_error(connection, page);
}

/********************************************************************
 *		provide CPU flags
 ********************************************************************/

static struct MHD_Response *
remoted_cpu(struct MHD_Connection *connection, char **next_token)
{
	int    bank   = getCurrentBank(pc);

	cJSON *answer = cJSON_CreateObject();
	cJSON *jbank = cJSON_CreateNumber(bank);
	cJSON_AddItemToObject(answer, "bank", jbank);
	cJSON *jpc = cJSON_CreateNumber(pc);
	cJSON_AddItemToObject(answer, "pc", jpc);
	cJSON *jsp = cJSON_CreateNumber(sp);
	cJSON_AddItemToObject(answer, "sp", jsp);
	cJSON *ja = cJSON_CreateNumber(a);
	cJSON_AddItemToObject(answer, "a", ja);
	cJSON *jx = cJSON_CreateNumber(x);
	cJSON_AddItemToObject(answer, "x", jx);
	cJSON *jy = cJSON_CreateNumber(y);
	cJSON_AddItemToObject(answer, "y", jy);
	cJSON *jstatus = cJSON_CreateNumber(status);
	cJSON_AddItemToObject(answer, "flags", jstatus);
	cJSON *jmyStatus = cJSON_CreateNumber(myStatus);
	cJSON_AddItemToObject(answer, "myStatus", jmyStatus);
	cJSON *jmyPid= cJSON_CreateNumber(RD_pid);
	cJSON_AddItemToObject(answer, "pid", jmyPid);

	return remoted_json(connection, answer);
}

/********************************************************************
 *		run the current prog 
 ********************************************************************/

static struct MHD_Response *
remoted_run(struct MHD_Connection *connection, char **next_token)
{
	char *run = _strdup("RUN\r");

	machine_paste(run); // machine paste will free the block at the end
	return remoted_ok(connection);
}

/********************************************************************
 *		reset the emulator and relaunch the program
 ********************************************************************/

/**
 * move the PC back to the start
 */
static struct MHD_Response *
remoted_restart(struct MHD_Connection *connection, char **next_token)
{
	machine_reset();

	//now reload the PRG from RD_prg_path
	prg_file = SDL_RWFromFile(RD_prg_path, "rb");
	if (!prg_file) {
		printf("Cannot open %s!\n", RD_prg_path);
		exit(1);
	}

	char *restart = _strdup("LOAD\":*\",8,1\rRUN\r");
	prg_consumed = false;		// force ieee.c:copen to use prg_file as file description
	machine_paste(restart);		// machine paste will free restart at the end

	myStatus = CPU_RUN;			// let the emulator run

	return remoted_ok(connection);
}

/********************************************************************
 *		threads to receive requests
 ********************************************************************/

/**
 *
 */
static enum MHD_Result
ahc_echo(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
	static int dummy;
	struct MHD_Response *response=NULL;
	int  ret = MHD_YES;
	char                *next_token = NULL;

	if (0 != strcmp(method, "GET"))
		return MHD_NO; /* unexpected method */
	if (&dummy != *ptr) {
		/* The first time only the headers are valid,
		   do not respond in the first round... */
		*ptr = &dummy;
		return MHD_YES;
	}
	if (0 != *upload_data_size)
		return MHD_NO; /* upload data in a GET!? */

	*ptr = NULL; /* clear context pointer */

	char *token = strtok_s((char *)url, "/", &next_token);

	if (token == NULL) {
		const char *page = "incorect command provided";
		remoted_error(connection, page);
	}
	else if (strcmp(token, "vera") == 0) {
		response = remoted_vera(connection, &next_token);
	}
	else if (strcmp(token, "dump") == 0) {
		response = remoted_dump(connection, &next_token);
	}
	else if (strcmp(token, "breakpoint") == 0) {
		response = remoted_breakpoint(connection, &next_token);
	}
	else if (strcmp(token, "debug") == 0) {
		response = remoted_debug(connection, &next_token);
	}
	else if (strcmp(token, "cpu") == 0) {
		response = remoted_cpu(connection, &next_token);
	}
	else if (strcmp(token, "watch") == 0) {
		response = remoted_watch(connection, &next_token);
	}
	else if (strcmp(token, "vwatch") == 0) {
		response = remoted_vera_watch(connection, &next_token);
	}
	else if (strcmp(token, "restart") == 0) {
		response = remoted_restart(connection, &next_token);
	}
	else if (strcmp(token, "run") == 0) {
		response = remoted_run(connection, &next_token);
	}

	if (response != NULL) {
		MHD_destroy_response(response);
	}

	return ret;
}

//-----------------------------------------------------------
//   public functions
//-----------------------------------------------------------

/**
 *
 */
bool
remoted_open(char *prg_path)
{
	RD_pid = _getpid();

	if (prg_path != NULL) {
		RD_prg_path = _strdup(prg_path);
	}

	initBreakpoints();
	initWatches();

	daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, 9009, NULL, NULL, &ahc_echo, NULL, MHD_OPTION_END);
	if (daemon == NULL)
		return false;

	return true;
}

void
remoted_close(void)
{
	MHD_stop_daemon(daemon);
}

enum REMOTED_CMD
remoted_getStatus(void)
{
	// detect BRK
	if (read6502(pc) == 00) {
		myStatus = CPU_STOP;
	}

	// decide how to execute the current instruction
	if (myStatus == CPU_RESTART) {
		pc       = _start;
		sp       = 0xf6;
		myStatus = CPU_RUN;
	}
	else if (myStatus == CPU_NEXT) {
		// synchronous execution => send the response to the debugger;
		myStatus = CPU_STOP;
	}
	else if (myStatus == CPU_EXECUTE_NEXT) { // EXECUTE_NEXT set by remote debuggers
		myStatus = CPU_NEXT;			// so execute the next instruction
	}
	else if (myStatus == CPU_RUN) {
		//TODO get current bank
		if (hitBreakpoint(pc, 0) || hitWatch()) {
			myStatus = CPU_STOP;
		}
	} else {
		// CPU_STOP
		if (!video_update()) {
			// SDL Quit event
			myStatus = CPU_EXIT;
		}
	}
	return myStatus;
}
