#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h> // for av_gettime
#include <fcntl.h>
#include <stdarg.h>
#include "structdef.h"
#include <sys/ioctl.h>
static size_t max_alloc_size= INT_MAX;
void *av_malloc(size_t size);
void *av_mallocz(size_t size);
void av_free(void *ptr);
void av_freep(void *arg);
void *av_realloc(void *ptr, size_t size);
int av_reallocp(void *ptr, size_t size);
// for time
int64_t av_gettime(void);
//for io
void avio_write(AVIOContext *s, const unsigned char *buf, int size);
int avio_printf(AVIOContext *s, const char *fmt, ...);
static void writeout(AVIOContext *s, const uint8_t *data, int len);
static void flush_buffer(AVIOContext *s);
void avio_flush(AVIOContext *s);
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
static int url_resetbuf(AVIOContext *s, int flags);
int ffio_init_context(AVIOContext *s,
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence));
AVIOContext *avio_alloc_context(
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence));
static int dyn_buf_write(void *opaque, uint8_t *buf, int buf_size);
static int dyn_packet_buf_write(void *opaque, uint8_t *buf, int buf_size);
static int64_t dyn_buf_seek(void *opaque, int64_t offset, int whence);
static int url_open_dyn_buf_internal(AVIOContext **s, int max_packet_size);
int avio_open_dyn_buf(AVIOContext **s);
int avio_close_dyn_buf(AVIOContext *s, uint8_t **pbuffer);
