#include "utils.h"
// for memory util
void *av_malloc(size_t size)
{
    void *ptr = NULL;
    /* let's disallow possibly ambiguous cases */
    if (size > (max_alloc_size - 32))
        return NULL;
    ptr = malloc(size);
    if(!ptr && !size) {
        size = 1;
        ptr= av_malloc(1);
    }
    return ptr;
}

void *av_mallocz(size_t size)
{
    void *ptr = av_malloc(size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void av_free(void *ptr)
{
  free(ptr);
}

void av_freep(void *arg)
{
    void **ptr = (void **)arg;
    av_free(*ptr);
    *ptr = NULL;
}

void *av_realloc(void *ptr, size_t size)
{
    /* let's disallow possibly ambiguous cases */
    if (size > (max_alloc_size - 32))
        return NULL;
    return realloc(ptr, size + !size);
}

int av_reallocp(void *ptr, size_t size)
{
    void **ptrptr = ptr;
    void *ret;

    if (!size) {
        av_freep(ptr);
        return 0;
    }
    ret = av_realloc(*ptrptr, size);

    if (!ret) {
        av_freep(ptr);
        return -1;
    }

    *ptrptr = ret;
    return 0;
}
// for time
int64_t av_gettime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

//for io
void avio_write(AVIOContext *s, const unsigned char *buf, int size);

int avio_printf(AVIOContext *s, const char *fmt, ...)
{
    va_list ap;
    char buf[4096];
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    avio_write(s, buf, strlen(buf));
    return ret;
}

static void writeout(AVIOContext *s, const uint8_t *data, int len)
{
    if (s->write_packet && !s->error) {
        int ret = s->write_packet(s->opaque, (uint8_t *)data, len);
        if (ret < 0) {
            s->error = ret;
        }
    }
    s->writeout_count ++;
    s->pos += len;
}

static void flush_buffer(AVIOContext *s)
{
    if (s->buf_ptr > s->buffer) {
        writeout(s, s->buffer, s->buf_ptr - s->buffer);
        if (s->update_checksum) {
            s->checksum     = s->update_checksum(s->checksum, s->checksum_ptr,
                                                 s->buf_ptr - s->checksum_ptr);
            s->checksum_ptr = s->buffer;
        }
    }
    s->buf_ptr = s->buffer;
}

void avio_flush(AVIOContext *s)
{
    flush_buffer(s);
    s->must_flush = 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void avio_write(AVIOContext *s, const unsigned char *buf, int size)
{
    if (s->direct && !s->update_checksum) {
        avio_flush(s);
        writeout(s, buf, size);
        return;
    }
    while (size > 0) {
        int len = MIN(s->buf_end - s->buf_ptr, size);
        memcpy(s->buf_ptr, buf, len);
        s->buf_ptr += len;

        if (s->buf_ptr >= s->buf_end)
            flush_buffer(s);

        buf += len;
        size -= len;
    }
}

static int url_resetbuf(AVIOContext *s, int flags)
{
    //av_assert1(flags == AVIO_FLAG_WRITE || flags == AVIO_FLAG_READ);
    //
    if (flags & AVIO_FLAG_WRITE) {
        s->buf_end = s->buffer + s->buffer_size;
        s->write_flag = 1;
    } else {
        s->buf_end = s->buffer;
        s->write_flag = 0;
    }
    return 0;
}
int ffio_init_context(AVIOContext *s,
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    s->buffer      = buffer;
    s->orig_buffer_size =
    s->buffer_size = buffer_size;
    s->buf_ptr     = buffer;
    s->opaque      = opaque;
    s->direct      = 0;

    url_resetbuf(s, write_flag ? AVIO_FLAG_WRITE : AVIO_FLAG_READ);

    s->write_packet    = write_packet;
    s->read_packet     = read_packet;
    s->seek            = seek;
    s->pos             = 0;
    s->must_flush      = 0;
    s->eof_reached     = 0;
    s->error           = 0;
    s->seekable        = seek ? AVIO_SEEKABLE_NORMAL : 0;
    s->max_packet_size = 0;
    s->update_checksum = NULL;

    if (!read_packet && !write_flag) {
        s->pos     = buffer_size;
        s->buf_end = s->buffer + buffer_size;
    }
    s->read_pause = NULL;
    s->read_seek  = NULL;

    return 0;
}

AVIOContext *avio_alloc_context(
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    AVIOContext *s = av_mallocz(sizeof(AVIOContext));
    if (!s)
        return NULL;
    ffio_init_context(s, buffer, buffer_size, write_flag, opaque,
                  read_packet, write_packet, seek);
    return s;
}

static int dyn_buf_write(void *opaque, uint8_t *buf, int buf_size)
{
    DynBuffer *d = opaque;
    unsigned new_size, new_allocated_size;

    /* reallocate buffer if needed */
    new_size = d->pos + buf_size;
    new_allocated_size = d->allocated_size;
    if (new_size < d->pos || new_size > INT_MAX/2)
        return -1;
    while (new_size > new_allocated_size) {
        if (!new_allocated_size)
            new_allocated_size = new_size;
        else
            new_allocated_size += new_allocated_size / 2 + 1;
    }

    if (new_allocated_size > d->allocated_size) {
        int err;
        if ((err = av_reallocp(&d->buffer, new_allocated_size)) < 0) {
            d->allocated_size = 0;
            d->size = 0;
            return err;
        }
        d->allocated_size = new_allocated_size;
    }
    memcpy(d->buffer + d->pos, buf, buf_size);
    d->pos = new_size;
    if (d->pos > d->size)
        d->size = d->pos;
    return buf_size;
}

static int dyn_packet_buf_write(void *opaque, uint8_t *buf, int buf_size)
{
    unsigned char buf1[4];
    int ret;

    /* packetized write: output the header */
    //AV_WB32(buf1, buf_size); 이거 뭔지 모르겠음..찾아봐야할듯.
    ret = dyn_buf_write(opaque, buf1, 4);
    if (ret < 0)
        return ret;

    /* then the data */
    return dyn_buf_write(opaque, buf, buf_size);
}

static int64_t dyn_buf_seek(void *opaque, int64_t offset, int whence)
{
    DynBuffer *d = opaque;

    if (whence == SEEK_CUR)
        offset += d->pos;
    else if (whence == SEEK_END)
        offset += d->size;
    if (offset < 0 || offset > 0x7fffffffLL)
        return -1;
    d->pos = offset;
    return 0;
}

static int url_open_dyn_buf_internal(AVIOContext **s, int max_packet_size)
{
    DynBuffer *d;
    unsigned io_buffer_size = max_packet_size ? max_packet_size : 1024;

    if (sizeof(DynBuffer) + io_buffer_size < io_buffer_size)
        return -1;
    d = av_mallocz(sizeof(DynBuffer) + io_buffer_size);
    if (!d)
        return -1;
    d->io_buffer_size = io_buffer_size;
    *s = avio_alloc_context(d->io_buffer, d->io_buffer_size, 1, d, NULL,
                            max_packet_size ? dyn_packet_buf_write : dyn_buf_write,
                            max_packet_size ? NULL : dyn_buf_seek);
    if(!*s) {
        av_free(d);
        return -1;
    }
    (*s)->max_packet_size = max_packet_size;
    return 0;
}

int avio_open_dyn_buf(AVIOContext **s)
{
    return url_open_dyn_buf_internal(s, 0);
}

int avio_close_dyn_buf(AVIOContext *s, uint8_t **pbuffer)
{
    DynBuffer *d;
    int size;
    static const char padbuf[FF_INPUT_BUFFER_PADDING_SIZE] = {0};
    int padding = 0;

    if (!s) {
        *pbuffer = NULL;
        return 0;
    }
    d = s->opaque;

    /* don't attempt to pad fixed-size packet buffers */
    if (!s->max_packet_size) {
        avio_write(s, padbuf, sizeof(padbuf));
        padding = FF_INPUT_BUFFER_PADDING_SIZE;
    }

    avio_flush(s);

    *pbuffer = d->buffer;
    size = d->size;
    av_free(d);
    av_free(s);
    return size - padding;
}
