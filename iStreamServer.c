#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <signal.h>

//#include "lib/avformat.h"
#include <sys/time.h> // for av_gettime
#include <sys/poll.h> // for poll
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include "lib/structdef.h"

const char program_name[] = "iStreamServer";
const int program_birth_year = 2014;

//static const OptionDef options[];

static struct sockaddr_in my_http_addr;
static struct sockaddr_in my_rtsp_addr;

static char logfilename[1024];
static RTSPContext *first_http_ctx;

static void new_connection(int server_fd, int is_rtsp);
static void close_connection(RTSPContext *c);

/* HTTP handling */
static int handle_connection(RTSPContext *c);
static int http_parse_request(RTSPContext *c);
static int http_send_data(RTSPContext *c);
static void compute_status(RTSPContext *c);
static int open_input_stream(RTSPContext *c, const char *info);
static int http_start_receive_data(RTSPContext *c);
static int http_receive_data(RTSPContext *c);

static int rtsp_parse_request(RTSPContext *c);
static void rtsp_cmd_describe(RTSPContext *c, const char *url);
static void rtsp_cmd_options(RTSPContext *c, const char *url);
static void rtsp_cmd_setup(RTSPContext *c, const char *url, RTSPMessageHeader *h);
static void rtsp_cmd_play(RTSPContext *c, const char *url, RTSPMessageHeader *h);
static void rtsp_cmd_interrupt(RTSPContext *c, const char *url, RTSPMessageHeader *h, int pause_only);

/* RTP handling */
static int rtp_new_av_stream(RTSPContext *c,
                             int stream_index, struct sockaddr_in *dest_addr,
                             RTSPContext *rtsp_c);

static const char *my_program_name;

static const char *config_filename;

static int ffserver_debug;
static int no_launch;
static int need_to_start_children;

/* maximum number of simultaneous HTTP connections */
static unsigned int nb_max_http_connections = 2000;
static unsigned int nb_max_connections = 5;
static unsigned int nb_connections;

static uint64_t max_bandwidth = 1000;
static uint64_t current_bandwidth;

static int64_t cur_time;           // Making this global saves on passing it around everywhere

//static AVLFG random_state;
static void htmlstrip(char *s) {
    while (s && *s) {
        s += strspn(s, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,. ");
        if (*s)
            *s++ = '?';
    }
}

static void update_datarate(DataRateData *drd, int64_t count)
{
    if (!drd->time1 && !drd->count1) {
        drd->time1 = drd->time2 = cur_time;
        drd->count1 = drd->count2 = count;
    } else if (cur_time - drd->time2 > 5000) {
        drd->time1 = drd->time2;
        drd->count1 = drd->count2;
        drd->time2 = cur_time;
        drd->count2 = count;
    }
}

int ff_socket_nonblock(int socket, int enable)
{
    if (enable)
        return fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) | O_NONBLOCK);
    else
        return fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) & ~O_NONBLOCK);
}
// for memory util
static size_t max_alloc_size= INT_MAX;
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

/* In bytes per second */
static int compute_datarate(DataRateData *drd, int64_t count)
{
    if (cur_time == drd->time1)
        return 0;

    return ((count - drd->count1) * 1000) / (cur_time - drd->time1);
}

/* open a listening socket */
static int socket_open_listen(struct sockaddr_in *my_addr)
{
    int server_fd, tmp;

    server_fd = socket(AF_INET,SOCK_STREAM,0);
    if (server_fd < 0) {
        perror ("socket");
        return -1;
    }

    tmp = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

    my_addr->sin_family = AF_INET;
    if (bind (server_fd, (struct sockaddr *) my_addr, sizeof (*my_addr)) < 0) {
        char bindmsg[32];
        snprintf(bindmsg, sizeof(bindmsg), "bind(port %d)", ntohs(my_addr->sin_port));
        perror (bindmsg);
        close(server_fd);
        return -1;
    }

    if (listen (server_fd, 5) < 0) {
        perror ("listen");
        close(server_fd);
        return -1;
    }
    ff_socket_nonblock(server_fd, 1);

    return server_fd;
}

static void http_log(const char *fmt, ...)
{
  /*
    va_list vargs;
    va_start(vargs, fmt);
    http_vlog(fmt, vargs);
    va_end(vargs);
    */
  printf("%s", fmt);
}

/* main loop of the HTTP server */
static int http_server(void)
{
    int server_fd = 0, rtsp_server_fd = 0;
    int ret, delay;
    struct pollfd *poll_table, *poll_entry;
    RTSPContext *c, *c_next;

    if(!(poll_table = av_mallocz((nb_max_http_connections + 2)*sizeof(*poll_table)))) {
        http_log("Impossible to allocate a poll table handling %d connections.\n", nb_max_http_connections);
        return -1;
    }

    if (my_rtsp_addr.sin_port) {
        rtsp_server_fd = socket_open_listen(&my_rtsp_addr);
        if (rtsp_server_fd < 0)
            return -1;
    }

    if (!rtsp_server_fd) {
        http_log("HTTP and RTSP disabled.\n");
        return -1;
    }

    printf("%s started.\n", program_name);

//    start_children(first_feed);

 //   start_multicast();

    for(;;) {
        http_log("start event loop.\n");
        poll_entry = poll_table;
        if (rtsp_server_fd) {
            poll_entry->fd = rtsp_server_fd;
            poll_entry->events = POLLIN;
            poll_entry++;
        }

        /* wait for events on each HTTP handle */
        c = first_http_ctx;
        delay = 1000;
        while (c != NULL) {
            int fd;
            fd = c->fd;
            switch(c->state) {
            case HTTPSTATE_SEND_HEADER:
            case RTSPSTATE_SEND_REPLY:
            case RTSPSTATE_SEND_PACKET:
                c->poll_entry = poll_entry;
                poll_entry->fd = fd;
                poll_entry->events = POLLOUT;
                poll_entry++;
                break;
            case HTTPSTATE_SEND_DATA_HEADER:
            case HTTPSTATE_SEND_DATA:
            case HTTPSTATE_SEND_DATA_TRAILER:
                if (!c->is_packetized) {
                    /* for TCP, we output as much as we can
                     * (may need to put a limit) */
                    c->poll_entry = poll_entry;
                    poll_entry->fd = fd;
                    poll_entry->events = POLLOUT;
                    poll_entry++;
                } else {
                    /* when ffserver is doing the timing, we work by
                       looking at which packet needs to be sent every
                       10 ms */
                    /* one tick wait XXX: 10 ms assumed */
                    if (delay > 10)
                        delay = 10;
                }
                break;
            case HTTPSTATE_WAIT_REQUEST:
            case HTTPSTATE_RECEIVE_DATA:
            case HTTPSTATE_WAIT_FEED:
            case RTSPSTATE_WAIT_REQUEST:
                /* need to catch errors */
                c->poll_entry = poll_entry;
                poll_entry->fd = fd;
                poll_entry->events = POLLIN;/* Maybe this will work */
                poll_entry++;
                break;
            default:
                c->poll_entry = NULL;
                break;
            }
            c = c->next;
        }

        /* wait for an event on one connection. We poll at least every
           second to handle timeouts */
        do {
            ret = poll(poll_table, poll_entry - poll_table, delay);
            if (ret < 0 /* && ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR) */) {
              printf ("poll errorr \n");
              return -1;
            }
        } while (ret < 0);

        cur_time = av_gettime() / 1000;

        if (need_to_start_children) {
            need_to_start_children = 0;
            //start_children(first_feed);
        }

        /* now handle the events */
        for(c = first_http_ctx; c != NULL; c = c_next) {
            c_next = c->next;
            if (handle_connection(c) < 0) {
             //   log_connection(c);
                /* close and free the connection */
                close_connection(c);
            }
        }

        poll_entry = poll_table;
        if (rtsp_server_fd) {
            /* new RTSP connection request ? */
            if (poll_entry->revents & POLLIN)
                new_connection(rtsp_server_fd, 1);
        }
    }
}

/* start waiting for a new HTTP/RTSP request */
static void start_wait_request(RTSPContext *c, int is_rtsp)
{
    c->buffer_ptr = c->buffer;
    c->buffer_end = c->buffer + c->buffer_size - 1; /* leave room for '\0' */

    if (is_rtsp) {
        c->timeout = cur_time + RTSP_REQUEST_TIMEOUT;
        c->state = RTSPSTATE_WAIT_REQUEST;
    } else {
        c->timeout = cur_time + HTTP_REQUEST_TIMEOUT;
        c->state = HTTPSTATE_WAIT_REQUEST;
    }
}

static void http_send_too_busy_reply(int fd)
{
    char buffer[400];
    int len = snprintf(buffer, sizeof(buffer),
                       "HTTP/1.0 503 Server too busy\r\n"
                       "Content-type: text/html\r\n"
                       "\r\n"
                       "<html><head><title>Too busy</title></head><body>\r\n"
                       "<p>The server is too busy to serve your request at this time.</p>\r\n"
                       "<p>The number of current connections is %u, and this exceeds the limit of %u.</p>\r\n"
                       "</body></html>\r\n",
                       nb_connections, nb_max_connections);
    if (len < sizeof(buffer)) {
      printf("error occur! in http_send_too_busy_reply!");
      abort();
    }
    send(fd, buffer, len, 0);
}


static void new_connection(int server_fd, int is_rtsp)
{
    http_log("new connection!.\n");
    struct sockaddr_in from_addr;
    socklen_t len;
    int fd;
    RTSPContext *c = NULL;

    len = sizeof(from_addr);
    fd = accept(server_fd, (struct sockaddr *)&from_addr,
                &len);
    if (fd < 0) {
        http_log("error during accept %s\n", strerror(errno));
        return;
    }
    ff_socket_nonblock(fd, 1);

    if (nb_connections >= nb_max_connections) {
        http_send_too_busy_reply(fd);
        goto fail;
    }

    /* add a new connection */
    c = av_mallocz(sizeof(RTSPContext));
    if (!c)
        goto fail;

    c->fd = fd;
    c->poll_entry = NULL;
    c->from_addr = from_addr;
    c->buffer_size = IOBUFFER_INIT_SIZE;
    c->buffer = av_malloc(c->buffer_size);
    if (!c->buffer)
        goto fail;

    c->next = first_http_ctx;
    first_http_ctx = c;
    nb_connections++;

    start_wait_request(c, is_rtsp);

    return;

 fail:
    if (c) {
        av_free(c->buffer);
        av_free(c);
    }
    close(fd);
}

static void close_connection(RTSPContext *c)
{
    RTSPContext **cp, *c1;
    int i, nb_streams;
    //AVFormatContext *ctx;
    //URLContext *h;
    //AVStream *st;

    /* remove connection from list */
    cp = &first_http_ctx;
    while ((*cp) != NULL) {
        c1 = *cp;
        if (c1 == c)
            *cp = c->next;
        else
            cp = &c1->next;
    }

    /* remove references, if any (XXX: do it faster) */
    for(c1 = first_http_ctx; c1 != NULL; c1 = c1->next) {
        if (c1->rtsp_c == c)
            c1->rtsp_c = NULL;
    }

    /* remove connection associated resources */
    if (c->fd >= 0)
        close(c->fd);
    /*
    if (c->fmt_in) {
        // close each frame parser
        for(i=0;i<c->fmt_in->nb_streams;i++) {
            st = c->fmt_in->streams[i];
            if (st->codec->codec)
                avcodec_close(st->codec);
        }
        avformat_close_input(&c->fmt_in);
    }
*/

    /* free RTP output streams if any 
    nb_streams = 0;
    if (c->stream)
        nb_streams = c->stream->nb_streams;

    for(i=0;i<nb_streams;i++) {
        ctx = c->rtp_ctx[i];
        if (ctx) {
            av_write_trailer(ctx);
            av_dict_free(&ctx->metadata);
            av_free(ctx->streams[0]);
            av_free(ctx);
        }
        h = c->rtp_handles[i];
        if (h)
            ffurl_close(h);
    }

    ctx = &c->fmt_ctx;

    if (!c->last_packet_sent && c->state == HTTPSTATE_SEND_DATA_TRAILER) {
        if (ctx->oformat) {
            // prepare header
            if (avio_open_dyn_buf(&ctx->pb) >= 0) {
                av_write_trailer(ctx);
                av_freep(&c->pb_buffer);
                avio_close_dyn_buf(ctx->pb, &c->pb_buffer);
            }
        }
    }

    for(i=0; i<ctx->nb_streams; i++)
        av_free(ctx->streams[i]);
    av_freep(&ctx->streams);
    av_freep(&ctx->priv_data);

    if (c->stream && !c->post && c->stream->stream_type == STREAM_TYPE_LIVE)
        current_bandwidth -= c->stream->bandwidth;

    // signal that there is no feed if we are the feeder socket 
    if (c->state == HTTPSTATE_RECEIVE_DATA && c->stream) {
        c->stream->feed_opened = 0;
        close(c->feed_fd);
    }
    */

    av_freep(&c->pb_buffer);
    av_freep(&c->packet_buffer);
    av_free(c->buffer);
    av_free(c);
    nb_connections--;
}

static int handle_connection(RTSPContext *c)
{
    //http_log("handle connection!\n");
    int len, ret;

    //printf("connection status = %d \n", c->state);
    switch(c->state) {
    case RTSPSTATE_WAIT_REQUEST:
        /* timeout ? */
        if ((c->timeout - cur_time) < 0)
            return -1;
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            return -1;

        /* no need to read if no events */
        if (!(c->poll_entry->revents & POLLIN))
            return 0;
        /* read the data */
    read_loop:
        len = recv(c->fd, c->buffer_ptr, 1, 0);
        if (len < 0) {
          /*
            if (ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR))
                */
          printf("recv error");
          return -1;
        } else if (len == 0) {
            return -1;
        } else {
            /* search for end of request. */
            uint8_t *ptr;
            c->buffer_ptr += len;
            ptr = c->buffer_ptr;
            if ((ptr >= c->buffer + 2 && !memcmp(ptr-2, "\n\n", 2)) ||
                (ptr >= c->buffer + 4 && !memcmp(ptr-4, "\r\n\r\n", 4))) {
                /* request found : parse it and reply */
                ret = rtsp_parse_request(c);
                if (ret < 0)
                    return -1;
            } else if (ptr >= c->buffer_end) {
                /* request too long: cannot do anything */
                return -1;
            } else goto read_loop;
        }
        break;

    case HTTPSTATE_SEND_HEADER:
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            return -1;

        /* no need to write if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;
        len = send(c->fd, c->buffer_ptr, c->buffer_end - c->buffer_ptr, 0);
        if (len < 0) {
          /*
            if (ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR)) {
            }
            */
            goto close_connection;
        } else {
            c->buffer_ptr += len;
            /*
            if (c->stream)
                c->stream->bytes_served += len;
            c->data_count += len;
            */
            if (c->buffer_ptr >= c->buffer_end) {
                av_freep(&c->pb_buffer);
                /* if error, exit */
                if (c->http_error)
                    return -1;
                /* all the buffer was sent : synchronize to the incoming
                 * stream */
                c->state = HTTPSTATE_SEND_DATA_HEADER;
                c->buffer_ptr = c->buffer_end = c->buffer;
            }
        }
        break;

    case HTTPSTATE_SEND_DATA:
    case HTTPSTATE_SEND_DATA_HEADER:
    case HTTPSTATE_SEND_DATA_TRAILER:
        /* for packetized output, we consider we can always write (the
           input streams set the speed). It may be better to verify
           that we do not rely too much on the kernel queues */
        if (!c->is_packetized) {
            if (c->poll_entry->revents & (POLLERR | POLLHUP))
                return -1;

            /* no need to read if no events */
            if (!(c->poll_entry->revents & POLLOUT))
                return 0;
        }
        /*
        if (http_send_data(c) < 0)
            return -1;
            */
        /* close connection if trailer sent */
        if (c->state == HTTPSTATE_SEND_DATA_TRAILER)
            return -1;
        break;
    case HTTPSTATE_RECEIVE_DATA:
        /* no need to read if no events */
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            return -1;
        if (!(c->poll_entry->revents & POLLIN))
            return 0;
        /*
        if (http_receive_data(c) < 0)
            return -1;
            */
        break;
    case HTTPSTATE_WAIT_FEED:
        /* no need to read if no events */
        if (c->poll_entry->revents & (POLLIN | POLLERR | POLLHUP))
            return -1;

        /* nothing to do, we'll be waken up by incoming feed packets */
        break;

    case RTSPSTATE_SEND_REPLY:
        //printf("rtspstate send reply \n");
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            goto close_connection;
        /* no need to write if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;
        printf("send! \n");
        len = send(c->fd, c->buffer_ptr, c->buffer_end - c->buffer_ptr, 0);
        if (len < 0) {
            printf("send error TT! \n");
            if (1 /*ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR) */) {
                goto close_connection;
            }
        } else {
            //printf("send success!! len = %d \n", len);
            c->buffer_ptr += len;
            c->data_count += len;
            if (c->buffer_ptr >= c->buffer_end) {
                /* all the buffer was sent : wait for a new request */
                goto close_connection;
                //av_freep(&c->pb_buffer);
                //start_wait_request(c, 1);
            }
        }
        break;
    case RTSPSTATE_SEND_PACKET:
        if (c->poll_entry->revents & (POLLERR | POLLHUP)) {
            av_freep(&c->packet_buffer);
            return -1;
        }
        /* no need to write if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;
        len = send(c->fd, c->packet_buffer_ptr,
                    c->packet_buffer_end - c->packet_buffer_ptr, 0);
        if (len < 0) {
            if (1/*ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR)*/) {
                /* error : close connection */
                av_freep(&c->packet_buffer);
                return -1;
            }
        } else {
            c->packet_buffer_ptr += len;
            if (c->packet_buffer_ptr >= c->packet_buffer_end) {
                /* all the buffer was sent : wait for a new request */
                av_freep(&c->packet_buffer);
                c->state = RTSPSTATE_WAIT_REQUEST;
            }
        }
        break;
    case HTTPSTATE_READY:
        /* nothing to do */
        http_log("http state ready \n");
        break;
    default:
        return -1;
    }
    return 0;

close_connection:
    printf("close connection!\n");
    av_freep(&c->pb_buffer);
    return -1;
}
/********************************************************************/
/* RTSP handling */

static void rtsp_reply_header(RTSPContext *c, enum RTSPStatusCode error_number)
{
    const char *str;
    time_t ti;
    struct tm *tm;
    char buf2[32];

    //str = RTSP_STATUS_CODE2STRING(error_number);
    str = "OK";
    if (!str)
        str = "Unknown Error";

    avio_printf(c->pb, "RTSP/1.0 %d %s\r\n", error_number, str);
    avio_printf(c->pb, "CSeq: %d\r\n", c->seq);

    /* output GMT time */
    ti = time(NULL);
    tm = gmtime(&ti);
    strftime(buf2, sizeof(buf2), "%a, %d %b %Y %H:%M:%S", tm);
    avio_printf(c->pb, "Date: %s GMT\r\n", buf2);
}

static void rtsp_reply_error(RTSPContext *c, enum RTSPStatusCode error_number)
{
    rtsp_reply_header(c, error_number);
    avio_printf(c->pb, "\r\n");
}

size_t av_strlcpy(char *dst, const char *src, size_t size)
{
    size_t len = 0;
    while (++len < size && *src)
        *dst++ = *src++;
    if (len <= size)
        *dst = 0;
    return len + strlen(src) - 1;
}
// in libavformat/rtsp.c
static void get_word_until_chars(char *buf, int buf_size,
                                 const char *sep, const char **pp)
{
    const char *p;
    char *q;

    p = *pp;
    p += strspn(p, SPACE_CHARS);
    q = buf;
    while (!strchr(sep, *p) && *p != '\0') {
        if ((q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    if (buf_size > 0)
        *q = '\0';
    *pp = p;
}

static void get_word_sep(char *buf, int buf_size, const char *sep,
                         const char **pp)
{
    if (**pp == '/') (*pp)++;
    get_word_until_chars(buf, buf_size, sep, pp);
}

static void get_word(char *buf, int buf_size, const char **pp)
{
    get_word_until_chars(buf, buf_size, SPACE_CHARS, pp);
}

// libavutil/avstring.h
static inline int av_toupper(int c)
{
    if (c >= 'a' && c <= 'z')
        c ^= 0x20;
    return c;
}

/// liavutil/avstring.c
int av_stristart(const char *str, const char *pfx, const char **ptr)
{
    while (*pfx && av_toupper((unsigned)*pfx) == av_toupper((unsigned)*str)) {
        pfx++;
        str++;
    }
    if (!*pfx && ptr)
        *ptr = str;
    return !*pfx;
}

void ff_rtsp_parse_line(RTSPMessageHeader *reply, const char *buf,
                        RTSPState *rt, const char *method)
{
    const char *p;

    /* NOTE: we do case independent match for broken servers */
    p = buf;
    if (av_stristart(p, "Session:", &p)) {
        int t;
        get_word_sep(reply->session_id, sizeof(reply->session_id), ";", &p);
        if (av_stristart(p, ";timeout=", &p) &&
            (t = strtol(p, NULL, 10)) > 0) {
            reply->timeout = t;
        }
    } else if (av_stristart(p, "Content-Length:", &p)) {
        reply->content_length = strtol(p, NULL, 10);
    } else if (av_stristart(p, "Transport:", &p)) {
        //rtsp_parse_transport(reply, p);
    } else if (av_stristart(p, "CSeq:", &p)) {
        reply->seq = strtol(p, NULL, 10);
    } else if (av_stristart(p, "Range:", &p)) {
        //rtsp_parse_range_npt(p, &reply->range_start, &reply->range_end);
    } else if (av_stristart(p, "RealChallenge1:", &p)) {
        p += strspn(p, SPACE_CHARS);
        av_strlcpy(reply->real_challenge, p, sizeof(reply->real_challenge));
    } else if (av_stristart(p, "Server:", &p)) {
        p += strspn(p, SPACE_CHARS);
        av_strlcpy(reply->server, p, sizeof(reply->server));
    } else if (av_stristart(p, "Notice:", &p) ||
               av_stristart(p, "X-Notice:", &p)) {
        reply->notice = strtol(p, NULL, 10);
    } else if (av_stristart(p, "Location:", &p)) {
        p += strspn(p, SPACE_CHARS);
        av_strlcpy(reply->location, p , sizeof(reply->location));
    } else if (av_stristart(p, "WWW-Authenticate:", &p) && rt) {
        p += strspn(p, SPACE_CHARS);
        //ff_http_auth_handle_header(&rt->auth_state, "WWW-Authenticate", p);
    } else if (av_stristart(p, "Authentication-Info:", &p) && rt) {
        p += strspn(p, SPACE_CHARS);
        //ff_http_auth_handle_header(&rt->auth_state, "Authentication-Info", p);
    } else if (av_stristart(p, "Content-Base:", &p) && rt) {
        p += strspn(p, SPACE_CHARS);
        if (method && !strcmp(method, "DESCRIBE"))
            av_strlcpy(rt->control_uri, p , sizeof(rt->control_uri));
    } else if (av_stristart(p, "RTP-Info:", &p) && rt) {
        p += strspn(p, SPACE_CHARS);
        if (method && !strcmp(method, "PLAY"))
            //rtsp_parse_rtp_info(rt, p);
            printf("test");
    } else if (av_stristart(p, "Public:", &p) && rt) {
        if (strstr(p, "GET_PARAMETER") &&
            method && !strcmp(method, "OPTIONS"))
            rt->get_parameter_supported = 1;
    } else if (av_stristart(p, "x-Accept-Dynamic-Rate:", &p) && rt) {
        p += strspn(p, SPACE_CHARS);
        rt->accept_dynamic_rate = atoi(p);
    } else if (av_stristart(p, "Content-Type:", &p)) {
        p += strspn(p, SPACE_CHARS);
        av_strlcpy(reply->content_type, p, sizeof(reply->content_type));
    }
}

static void rtsp_cmd_options(RTSPContext *c, const char *url)
{
    rtsp_reply_header(c, RTSP_STATUS_OK);
    avio_printf(c->pb, "RTSP/1.0 %d %s\r\n", RTSP_STATUS_OK, "OK");
    avio_printf(c->pb, "CSeq: %d\r\n", c->seq);
    avio_printf(c->pb, "Public: %s\r\n", "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE");
    avio_printf(c->pb, "\r\n");
}

static int rtsp_parse_request(RTSPContext *c)
{
    //printf("rstp parse request!\n");
    const char *p, *p1, *p2;
    char cmd[32];
    char url[1024];
    char protocol[32];
    char line[1024];
    int len;
    RTSPMessageHeader header1 = { 0 }, *header = &header1;

    c->buffer_ptr[0] = '\0';
    p = c->buffer;

    get_word(cmd, sizeof(cmd), &p);
    get_word(url, sizeof(url), &p);
    get_word(protocol, sizeof(protocol), &p);

    av_strlcpy(c->method, cmd, sizeof(c->method));
    av_strlcpy(c->url, url, sizeof(c->url));
    av_strlcpy(c->protocol, protocol, sizeof(c->protocol));

    if (avio_open_dyn_buf(&c->pb) < 0) {
        /* XXX: cannot do more */
        c->pb = NULL; /* safety */
        return -1;
    }

    //printf("cmd = %s \n", cmd);
    //printf("url = %s \n", url);
    //printf("protocol = %s \n", protocol);
    /* check version name */
    if (strcmp(protocol, "RTSP/1.0") != 0) {
        rtsp_reply_error(c, RTSP_STATUS_VERSION);
        goto the_end;
    }

    /* parse each header line */
    /* skip to next line */
    while (*p != '\n' && *p != '\0')
        p++;
    if (*p == '\n')
        p++;
    while (*p != '\0') {
        p1 = memchr(p, '\n', (char *)c->buffer_ptr - p);
        if (!p1)
            break;
        p2 = p1;
        if (p2 > p && p2[-1] == '\r')
            p2--;
        /* skip empty line */
        if (p2 == p)
            break;
        len = p2 - p;
        if (len > sizeof(line) - 1)
            len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        ff_rtsp_parse_line(header, line, NULL, NULL);
        p = p1 + 1;
    }

    /* handle sequence number */
    c->seq = header->seq;

    //printf("cmd = %s \n", cmd);

    if (!strcmp(cmd, "DESCRIBE")) {
        //rtsp_cmd_describe(c, url);
        printf("DESCRIBE!!!\n");
    }
    else if (!strcmp(cmd, "OPTIONS")) {
        rtsp_cmd_options(c, url);
        printf("Options! \n");
    }
    else if (!strcmp(cmd, "SETUP"))
        //rtsp_cmd_setup(c, url, header);
        printf("Setup!!!\n");
    else if (!strcmp(cmd, "PLAY"))
        //rtsp_cmd_play(c, url, header);
        printf("Play!!! \n");
    else if (!strcmp(cmd, "PAUSE"))
        //rtsp_cmd_interrupt(c, url, header, 1);
        printf("PAUSE!!!\n");
    else if (!strcmp(cmd, "TEARDOWN"))
        //rtsp_cmd_interrupt(c, url, header, 0);
        printf("TEARDOWN!!!\n");
    else
        //rtsp_reply_error(c, RTSP_STATUS_METHOD);
        printf("Error!!");

 the_end:
    //printf("parsing end!\n");
    len = avio_close_dyn_buf(c->pb, &c->pb_buffer);
    c->pb = NULL; /* safety */
    if (len < 0) {
        /* XXX: cannot do more */
      printf("error! len < 0 when avio close dyn buf");
        return -1;
    }
    c->buffer_ptr = c->pb_buffer;
    c->buffer_end = c->pb_buffer + len;
    c->state = RTSPSTATE_SEND_REPLY;
    return 0;
}

static int resolve_host(struct in_addr *sin_addr, const char *hostname)
{

    // ff_inet_aton libavformat/os_support.c 에 있음. 혹시 안되면 찾아서 해 볼 것.
    if (!inet_aton(hostname, sin_addr)) {
#if HAVE_GETADDRINFO
        struct addrinfo *ai, *cur;
        struct addrinfo hints = { 0 };
        hints.ai_family = AF_INET;
        if (getaddrinfo(hostname, NULL, &hints, &ai))
            return -1;
        /* getaddrinfo returns a linked list of addrinfo structs.
         * Even if we set ai_family = AF_INET above, make sure
         * that the returned one actually is of the correct type. */
        for (cur = ai; cur; cur = cur->ai_next) {
            if (cur->ai_family == AF_INET) {
                *sin_addr = ((struct sockaddr_in *)cur->ai_addr)->sin_addr;
                freeaddrinfo(ai);
                return 0;
            }
        }
        freeaddrinfo(ai);
        return -1;
#else
        struct hostent *hp;
        hp = gethostbyname(hostname);
        if (!hp)
            return -1;
        memcpy(sin_addr, hp->h_addr_list[0], sizeof(struct in_addr));
#endif
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sigact = { { 0 } };
    int ret = 0;

    // set rtsp addr.
    my_rtsp_addr.sin_port = htons(5454); 
    resolve_host(&my_rtsp_addr.sin_addr, "0.0.0.0");

//    config_filename = av_strdup("/etc/ffserver.conf");

//    parse_loglevel(argc, argv, options);
//    av_register_all();
    //avformat_network_init();

//    show_banner(argc, argv, options);

 //   my_program_name = argv[0];

//    parse_options(NULL, argc, argv, options, NULL);

    unsetenv("http_proxy");             /* Kill the http_proxy */

//    av_lfg_init(&random_state, av_get_random_seed());

    /*
    sigact.sa_handler = handle_child_exit;
    sigact.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    sigaction(SIGCHLD, &sigact, 0);

    */

    /*
    if ((ret = parse_ffconfig(config_filename)) < 0) {
        fprintf(stderr, "Error reading configuration file '%s': %s\n",
                config_filename, av_err2str(ret));
        exit(1);
    }
    av_freep(&config_filename);
    */
    /* open log file if needed 
    if (logfilename[0] != '\0') {
        if (!strcmp(logfilename, "-"))
            logfile = stdout;
        else
            logfile = fopen(logfilename, "a");
        av_log_set_callback(http_av_log);
    }
    */

    //build_file_streams();

    //build_feed_streams();

    //compute_bandwidth();

    /* signal init */
    signal(SIGPIPE, SIG_IGN);

    if (http_server() < 0) {
       // http_log("Could not start server\n");
        printf("could not start server\n");
        exit(1);
    }

    return 0;
}
