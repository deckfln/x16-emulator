#ifndef __APPLE__
#define _XOPEN_SOURCE   600
#define _POSIX_C_SOURCE 1
#endif

#include "files.h"

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <SDL.h>
#include <zlib.h>

struct x16file
{
	char path[PATH_MAX];

	SDL_RWops *file;
	int64_t size;
	int64_t pos;

	struct x16file *next;
};

struct x16file *open_files = NULL;

static bool 
get_tmp_name(char *path_buffer, const char *original_path, char const *extension)
{
	if(strlen(original_path) > PATH_MAX - strlen(extension)) {
		printf("Path too long, cannot create temp file: %s\n", original_path);
		return false;
	}

	strcpy(path_buffer, original_path);
	strcat(path_buffer, extension);

	return true;
}

bool 
file_is_compressed_type(char const *path)
{
	int len = (int)strlen(path);

	if (strcmp(path + len - 3, ".gz") == 0 || strcmp(path + len - 3, "-gz") == 0) {
		return true;
	} else if (strcmp(path + len - 2, ".z") == 0 || strcmp(path + len - 2, "-z") == 0 || strcmp(path + len - 2, "_z") == 0 || strcmp(path + len - 2, ".Z") == 0) {
		return true;
	}

	return false;
}

void
files_shutdown()
{
	struct x16file *f = open_files;
	struct x16file *next_f = f ? f->next : NULL;
	for(; f != NULL; f = next_f) {
		next_f = f->next;

		SDL_RWclose(f->file);
		free(f);
	}
}

struct x16file *
x16open(const char *path, const char *attribs)
{
	struct x16file *f = malloc(sizeof(struct x16file));
	strcpy(f->path, path);

	if(file_is_compressed_type(path)) {
		char tmp_path[PATH_MAX];
		if(!get_tmp_name(tmp_path, path, ".tmp")) {
			printf("Path too long, cannot create temp file: %s\n", path);
			goto error;
		}

		gzFile zfile = gzopen(path, "rb");
		if(zfile == Z_NULL) {
			printf("Could not open file for decompression: %s\n", path);
			goto error;
		}

		SDL_RWops *tfile = SDL_RWFromFile(tmp_path, "wb");
		if(tfile == NULL) {
			gzclose(zfile);
			printf("Could not open file for write: %s\n", tmp_path);
			goto error;
		}

		const int buffer_size = 16 * 1024 * 1024;
		char *buffer = malloc(buffer_size);

		int read = gzread(zfile, buffer, buffer_size);
		int64_t total_read = read;
		while(read > 0) {
			SDL_RWwrite(tfile, buffer, read, 1);
			read = gzread(zfile, buffer, buffer_size);
			total_read += read;
		}

		SDL_RWclose(tfile);
		gzclose(zfile);
		free(buffer);

		f->file = SDL_RWFromFile(tmp_path, attribs);
		f->size = total_read;
	} else {
		f->file = SDL_RWFromFile(path, attribs);
		f->size = SDL_RWsize(f->file);
	}
	f->pos = 0;
	f->next = open_files ? open_files : NULL;
	open_files = f;

	return f;

error:
	free(f);
	return NULL;
}

void 
x16close(struct x16file *f)
{
	if(f == NULL) {
		return;
	}

	SDL_RWclose(f->file);

	if(file_is_compressed_type(f->path)) {
		char tmp_path[PATH_MAX];
		if(!get_tmp_name(tmp_path, f->path, ".tmp")) {
			printf("Path too long, cannot create temp file: %s\n", f->path);
			goto zfile_error;
		}

		gzFile zfile = gzopen(f->path, "wb9");
		if(zfile == Z_NULL) {
			printf("Could not open file for compression: %s\n", f->path);
			goto zfile_error;
		}

		SDL_RWops *tfile = SDL_RWFromFile(tmp_path, "rb");
		if(tfile == NULL) {
			gzclose(zfile);
			printf("Could not open file for read: %s\n", tmp_path);
			goto tfile_error;
		}

		const int buffer_size = 16 * 1024 * 1024;
		char *buffer = malloc(buffer_size);

		int read = SDL_RWread(tfile, buffer, 1, buffer_size);
		int64_t total_read = read;
		while(read > 0) {
			gzwrite(zfile, buffer, read);
			read = SDL_RWread(tfile, buffer, 1, buffer_size);
			total_read += read;
		}

		free(buffer);

		if(tfile != NULL) {
			SDL_RWclose(tfile);
		}

	tfile_error:
		if(zfile != Z_NULL) {
			gzclose(zfile);
		}
	}
zfile_error:
	free(f);
}

int64_t 
x16size(struct x16file *f)
{
	if(f == NULL) {
		return 0;
	}

	return f->size;
}

int 
x16seek(struct x16file *f, int64_t pos, int origin)
{
	if(f == NULL) {
		return 0;
	}
	switch(origin) {
		case SEEK_SET:
			f->pos = (pos > f->size) ? f->size : pos;
			break;
		case SEEK_CUR:
			f->pos += pos;
			if(f->pos > f->size || f->pos < 0) {
				f->pos = f->size;
			}
			break;
		case SEEK_END:
			f->pos = f->size - pos;
			if(f->pos < 0) {
				f->pos = f->size;
			}
	}
	return SDL_RWseek(f->file, f->pos, SEEK_SET);
}

int64_t 
x16tell(struct x16file *f)
{
	if(f == NULL) {
		return 0;
	}
	return f->pos;
}

int 
x16write8(struct x16file *f, uint8_t val)
{
	if(f == NULL) {
		return 0;
	}
	int written = SDL_RWwrite(f->file, &val, 1, 1);
	f->pos += written;
	return written;
}

int 
x16write16(struct x16file *f, uint16_t val)
{
	if(f == NULL) {
		return 0;
	}
	int written = SDL_RWwrite(f->file, &val, 1, 2);
	f->pos += written;
	return written;
}

int 
x16write32(struct x16file *f, uint32_t val)
{
	if(f == NULL) {
		return 0;
	}
	int written = SDL_RWwrite(f->file, &val, 1, 4);
	f->pos += written;
	return written;
}

uint8_t 
x16read8(struct x16file *f)
{
	if(f == NULL) {
		return 0;
	}
	uint8_t val;
	int read = SDL_RWread(f->file, &val, 1, 1);
	f->pos += read;
	return read;
}

uint16_t 
x16read16(struct x16file *f)
{
	if(f == NULL) {
		return 0;
	}
	uint16_t val;
	int read = SDL_RWread(f->file, &val, 1, 2);
	f->pos += read;
	return read;
}

uint32_t 
x16read32(struct x16file *f)
{
	if(f == NULL) {
		return 0;
	}
	uint32_t val;
	int read = SDL_RWread(f->file, &val, 1, 4);
	f->pos += read;
	return read;
}


uint64_t 
x16write(struct x16file *f, const uint8_t *data, uint64_t data_size, uint64_t data_count)
{
	if(f == NULL) {
		return 0;
	}
	int64_t written = SDL_RWwrite(f->file, data, data_size, data_count);
	f->pos += written * data_size;
	return written;
}

uint64_t 
x16read(struct x16file *f, uint8_t *data, uint64_t data_size, uint64_t data_count)
{
	if(f == NULL) {
		return 0;
	}
	int64_t read = SDL_RWread(f->file, data, data_size, data_count);
	f->pos += read * data_size;
	return read;
}
