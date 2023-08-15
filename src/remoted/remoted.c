#include "remoted.h"

#include <winsock2.h>
#include <microhttpd.h>
#include <png.h>

#include "../video.h"

//-----------------------------------------------------------
//   private functions
//-----------------------------------------------------------

static struct MHD_Daemon *daemon = NULL;
static fd_set rs;
static fd_set ws;
static fd_set es;
static MHD_UNSIGNED_LONG_LONG mhd_timeout;
static MHD_socket  max = 0;

/**
 *
 */
struct MHD_Response *
remoted_error(struct MHD_Connection *connection, const char *page)
{
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
	MHD_queue_response(connection, MHD_HTTP_OK, response);
	return response;
}

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
		uint32_t *row   = (uint32_t *)row_pointers[y];
		uint32_t *color  = bitmap + (width * y);
		for (x = 0; x < width; ++x) {
			*(row++) = *(color++);
		}
	}
	/* Actually write the image data. */
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
 *
 */
static struct MHD_Response *
remoted_sprite(struct MHD_Connection* connection, char** next_token)
{
#ifdef _MSC_VER
	char *token = strtok_s(NULL, "/", next_token);
#else
	char *token = strtok(NULL, "/");
#endif

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
			uint32_t size   = 0;
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
 *
 */
static struct MHD_Response *
remoted_vera(struct MHD_Connection *connection, char **next_token)
{
#ifdef _MSC_VER
	char *token = strtok_s(NULL, "/", next_token);
#else
	char *token = strtok(NULL, "/");
#endif

	if (token != NULL && strcmp(token, "sprite") == 0) {
		return remoted_sprite(connection, next_token);
	}

	const char *page = "incorect vera command provided";
	return remoted_error(connection, page);
}

/**
 *
 */
static enum MHD_Result
ahc_echo(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
	static int dummy;
	struct MHD_Response *response=NULL;
	int  ret = MHDR_DONE;
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

#ifdef _MSC_VER
	char *token = strtok_s((char *)url, "/", &next_token);
#else
	char *token = strtok((char *)url, "/");
#endif

	if (strcmp(token, "vera") == 0) {
		response = remoted_vera(connection, &next_token);
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
remoted_open(void)
{
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

void
remoted_getcommand(void)
{
}
