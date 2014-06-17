#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/time.h> // for av_gettime
#include <sys/poll.h> // for poll
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
// av series 는 util만 써보자. 최대한
#include "libavutil/avstring.h"
#include "libavutil/avassert.h"
#include "libavutil/random_seed.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/mem.h"
#include "libavutil/lfg.h"
#include "libavformat/avio.h"
#include "libavformat/rtsp.h"
#include "iServer.h"

#define HTTP_REQUEST_TIMEOUT (15 * 1000)
#define RTSP_REQUEST_TIMEOUT (3600 * 24 * 1000)
#define IOBUFFER_INIT_SIZE 8192
const char program_name[] = "iStreamServer";
const int program_birth_year = 2014;
static const char *config_filename;
static int64_t cur_time;           // Making this global saves on passing it around everywhere

static struct sockaddr_in my_rtsp_addr;
static char logfilename[1024];

static void new_connection(int server_fd);
static void close_connection(RTSPContext *c);
static FILE *logfile = NULL;
static unsigned int nb_connections;

static RTSPContext *first_rtsp_ctx;
iStream *first_stream;
static AVLFG random_state;

/* Utility Functions */
static void htmlstrip(char *s) {
    while (s && *s) {
        s += strspn(s, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,. ");
        if (*s)
            *s++ = '?';
    }
}

static char *ctime1(char *buf2, int buf_size)
{
    time_t ti;
    char *p;

    ti = time(NULL);
    p = ctime(&ti);
    av_strlcpy(buf2, p, buf_size);
    p = buf2 + strlen(p) - 1;
    if (*p == '\n')
        *p = '\0';
    return buf2;
}

static void get_arg(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;
    int quote;

    p = *pp;
    while (av_isspace(*p)) p++;
    q = buf;
    quote = 0;
    if (*p == '\"' || *p == '\'')
        quote = *p++;
    for(;;) {
        if (quote) {
            if (*p == quote)
                break;
        } else {
            if (av_isspace(*p))
                break;
        }
        if (*p == '\0')
            break;
        if ((q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    *q = '\0';
    if (quote && *p == quote)
        p++;
    *pp = p;
}

static void skip_spaces(const char **pp)
{
    const char *p;
    p = *pp;
    while (*p == ' ' || *p == '\t')
        p++;
    *pp = p;
}

static void get_word(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;

    p = *pp;
    skip_spaces(&p);
    q = buf;
    while (!av_isspace(*p) && *p != '\0') {
        if ((q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    if (buf_size > 0)
        *q = '\0';
    *pp = p;
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
//    ff_socket_nonblock(server_fd, 1);

    return server_fd;
}
/* conf file parsing */
static int parse_ffconfig(const char *filename)
{
    FILE *f;
    char line[1024];
    char cmd[64];
    char arg[1024], arg2[1024];
    const char *p;
    int val, errors, warnings, line_num;
    iStream **last_stream, *stream, *redirect;
    int ret = 0;

    f = fopen(filename, "r");
    if (!f) {
        ret = AVERROR(errno);
        av_log(NULL, AV_LOG_ERROR, "Could not open the configuration file '%s'\n", filename);
        return ret;
    }

    errors = warnings = 0;
    line_num = 0;
    first_stream = NULL;
    last_stream = &first_stream;
    stream = NULL;
    redirect = NULL;
#define ERROR(...)   printf
#define WARNING(...) printf

    for(;;) {
        if (fgets(line, sizeof(line), f) == NULL)
            break;
        line_num++;
        p = line;
        while (av_isspace(*p))
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        get_arg(cmd, sizeof(cmd), &p);
        printf("cmd = %s \n", cmd);

        if (!av_strcasecmp(cmd, "RTSPPort")) {
            get_arg(arg, sizeof(arg), &p);
            val = atoi(arg);
            if (val < 1 || val > 65536) {
                ERROR("%s:%d: Invalid port: %s\n", arg);
            }
            my_rtsp_addr.sin_port = htons(atoi(arg));
        } else if (!av_strcasecmp(cmd, "RTSPBindAddress")) {
            get_arg(arg, sizeof(arg), &p);
            if (resolve_host(&my_rtsp_addr.sin_addr, arg) != 0) {
                ERROR("Invalid host/IP address: %s\n", arg);
            }
        } else if (!av_strcasecmp(cmd, "File") || !av_strcasecmp(cmd, "ReadOnlyFile")) {
            if (stream) {
                get_arg(stream->filename, sizeof(stream->filename), &p);
                // set index filename too
                int len = strlen(stream->filename);
                printf("filename = %s, len = %d\n", stream->filename, len);
                strcpy(stream->idx_filename, stream->filename);
                stream->idx_filename[len] = 'x';
                stream->idx_filename[len+1] = '\0';
                len = strlen(stream->idx_filename);
                printf("idx filename = %s, len = %d\n", stream->idx_filename, len);
            }
        } else if (!av_strcasecmp(cmd, "<Stream")) {
            /*********************************************/
            /* Stream related options */
            char *q;
            if (stream) {
                ERROR("Already in a tag\n");
            } else {
                iStream *s;
                s = av_mallocz(sizeof(*s));
                if (!s) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
                stream = s;
                get_arg(stream->name, sizeof(stream->name), &p);
                q = strrchr(stream->name, '>');
                if (q)
                    *q = '\0';

                printf("stream name = %s \n", stream->name);
                for (s = first_stream; s; s = s->next) {
                    if (!strcmp(stream->name, s->name)) {
                        ERROR("Stream '%s' already registered\n", s->filename);
                    }
                }

                *last_stream = stream;
                last_stream = &stream->next;
            }
        } else if (!av_strcasecmp(cmd, "</Stream>")) {
            if (!stream) {
                ERROR("No corresponding <Stream> for </Stream>\n");
            } else {
              printf("stream end! codec name = %s\n", stream->codec_name);
              stream = NULL;
            }
        } else {
            //ERROR("Incorrect keyword: '%s'\n", cmd);
            printf("Incorrect keyword: '%s'\n", cmd);
        }
    }
#undef ERROR

end:
    fclose(f);
    if (ret < 0)
        return ret;
    if (errors)
        return AVERROR(EINVAL);
    else
        return 0;
}

static void http_vlog(const char *fmt, va_list vargs)
{
    static int print_prefix = 1;
    if (logfile) {
        if (print_prefix) {
            char buf[32];
            ctime1(buf, sizeof(buf));
            fprintf(logfile, "%s ", buf);
        }
        print_prefix = strstr(fmt, "\n") != NULL;
        vfprintf(logfile, fmt, vargs);
        fflush(logfile);
    }
}

static void http_log(const char *fmt, ...)
{
  va_list vargs;
  va_start(vargs, fmt);
  http_vlog(fmt, vargs);
  va_end(vargs);
 // printf("%s", fmt);
}

static int handle_connection(RTSPContext *c)
{
    //http_log("handle connection!\n");
    if (c->poll_entry == NULL) {
      printf("c -> poll entry is null!! \n");
      return 0;
    }
    int len, ret;

   // printf("connection status = %d \n", c->state);
    switch(c->state) {
    case HTTPSTATE_READY:
      //printf("http state ready \n");
      break;
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
          printf("recv error\n");
          return -1;
        } else if (len == 0) {
            return -1;
        } else {
          //printf("recv success! \n");
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
            printf("request too long!! \n");
              return -1;
          } else goto read_loop;
        }
        break;

    case HTTPSTATE_SEND_DATA:
        /* for packetized output, we consider we can always write (the
           input streams set the speed). It may be better to verify
           that we do not rely too much on the kernel queues */
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            return -1;

        /* no need to read if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;

        if (http_send_data(c) < 0)
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

    case RTSPSTATE_SEND_REPLY:
        //printf("rtspstate send reply \n");
        if (c->poll_entry->revents & (POLLERR | POLLHUP))
            goto close_connection;
        /* no need to write if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;
        printf("send! reply \n");
        len = send(c->fd, c->buffer_ptr, c->buffer_end - c->buffer_ptr, 0);
        if (len < 0) {
            printf("send error TT! \n");
            goto close_connection;
        } else {
            printf("send reply success!! len = %d \n", len);
            c->buffer_ptr += len;
            if (c->buffer_ptr >= c->buffer_end) {
                /* all the buffer was sent : wait for a new request */
                av_freep(&c->pb_buffer);
                start_wait_request(c);
                //goto close_connection;
            }
        }
        break;
    case RTSPSTATE_SEND_PACKET:
        printf("rtsp send packet! \n");
        if (c->poll_entry->revents & (POLLERR | POLLHUP)) {
            av_freep(&c->pb_buffer);
            return -1;
        }
        /* no need to write if no events */
        if (!(c->poll_entry->revents & POLLOUT))
            return 0;
        len = send(c->fd, c->buffer_ptr,
                    c->buffer_end - c->buffer_ptr, 0);
        if (len < 0) {
          /* error : close connection */
          av_freep(&c->pb_buffer);
          return -1;
        } else {
            c->buffer_ptr += len;
            if (c->buffer_ptr >= c->buffer_end) {
                // all the buffer was sent : wait for a new request
                av_freep(&c->buffer);
                c->state = RTSPSTATE_WAIT_REQUEST;
            }
        }
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

/* main loop of the HTTP server */
static int http_server(void)
{
    int server_fd = 0, rtsp_server_fd = 0;
    int ret, delay;
    struct pollfd *poll_table, *poll_entry;
    RTSPContext *c, *c_next;

    if(!(poll_table = av_mallocz( 100 *sizeof(*poll_table)))) {
        http_log("Impossible to allocate a poll table handling %d connections.\n", 100);
        return -1;
    }

    if (my_rtsp_addr.sin_port) {
      rtsp_server_fd = socket_open_listen(&my_rtsp_addr);
      if (rtsp_server_fd < 0) {
        http_log("HTTP and RTSP disabled.\n");
        return -1;
      }
    }

    printf("%s started.\n", program_name);

    for(;;) {
        //http_log("start event loop.\n");
        poll_entry = poll_table;
        if (rtsp_server_fd) {
            poll_entry->fd = rtsp_server_fd;
            poll_entry->events = POLLIN;
            poll_entry++;
        }

        /* wait for events on each HTTP handle */
        c = first_rtsp_ctx;
        delay = 1000;
        while (c != NULL) {
            int fd;
            fd = c->fd;
            switch(c->state) {
            case RTSPSTATE_SEND_REPLY:
            case RTSPSTATE_SEND_PACKET:
                c->poll_entry = poll_entry;
                poll_entry->fd = fd;
                poll_entry->events = POLLOUT;
                poll_entry++;
                break;
            case HTTPSTATE_SEND_DATA:
                /* for TCP, we output as much as we can
                 * (may need to put a limit) */
                // printf("set send data poll entry! \n");
                //printf("request protocol = %s, len = %lu \n", c->protocol, strlen(c->protocol));
                if (strcmp(c->protocol, "RTP/UDP") == 0) {
                  //printf("fd shouldbe udp fd \n");
                  fd = c->udp_fd;
                }
                c->poll_entry = poll_entry;
                poll_entry->fd = fd;
                poll_entry->events = POLLOUT;
                poll_entry++;
                break;
            case HTTPSTATE_RECEIVE_DATA:
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

        /* now handle the events */
        for(c = first_rtsp_ctx; c != NULL; c = c_next) {
            c_next = c->next;
           // printf("request protocol = %s, len = %lu \n", c->protocol, strlen(c->protocol));
            if (handle_connection(c) < 0) {
             //   log_connection(c);
              /* close and free the connection */
                close_connection(c);
            }
        }

        // 처음에  rtsp_server_fd로 셋팅했던 거. 로 포인터 값 변경.
        poll_entry = poll_table;
        if (rtsp_server_fd) {
            /* new RTSP connection request ? */
            if (poll_entry->revents & POLLIN)
                new_connection(rtsp_server_fd);
        }
    }
}

/* start waiting for a new HTTP/RTSP request */
static void start_wait_request(RTSPContext *c)
{
  c->buffer_ptr = c->buffer;
  c->buffer_end = c->buffer + c->buffer_size - 1;
  c->timeout = cur_time + RTSP_REQUEST_TIMEOUT;
  c->state = RTSPSTATE_WAIT_REQUEST;
}

static void build_file_streams(void)
{
  iStream *stream, *stream_next;
  int i, ret;
  for(stream = first_stream; stream != NULL; stream = stream_next) {
    stream_next = stream->next;

    printf("filename = %s\n", stream->filename);
    printf("idx filename = %s\n", stream->idx_filename);
    if (!stream->filename[0] && !stream->idx_filename[0]) {
        http_log("Unspecified feed file for stream '%s' or idx file '%s'\n", stream->filename, stream->idx_filename);
    }
    else {
        /* find all the AVStreams inside and reference them in
           'stream' */
      //index parsing
      iIndexHeader *hdr = malloc(sizeof(*hdr));
      if (hdr < 0)
        printf("malloc error! of iIndexHeader \n");

      // error 처리 생략
      //
      printf("start parse index file!!\n");
      iIndex *first_idx = start_parse_index_file(stream->idx_filename, hdr);

      if (first_idx == NULL) {
        http_log("%s Index file parsing error!!!\n", stream->idx_filename);
        return;
      }
      dump_iIndexHeader(hdr);
      stream->idx_hdr = hdr;
      stream->first_idx = first_idx;
      stream->codec_name = hdr->encoding_format == 0 ? "H264" : "H265";
      stream->total_length = hdr->total_length;
      stream->bit_rate = hdr->bit_rate;
      stream->duration = hdr->duration;
      //free(hdr);
      //dump_through_iIndex(stream->first_idx);
    }
  }
}

int resolve_host(struct in_addr *sin_addr, const char *hostname)
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

static void new_connection(int server_fd)
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
 //   ff_socket_nonblock(fd, 1);

    if (nb_connections >= 100) {
     //   http_send_too_busy_reply(fd);
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

    c->buffer_ptr = c->buffer;
    c->buffer_end = c->buffer + IOBUFFER_INIT_SIZE;
    c->next = first_rtsp_ctx;
    first_rtsp_ctx = c;
    nb_connections++;

    start_wait_request(c);
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

    /* remove connection from list */
    cp = &first_rtsp_ctx;
    while ((*cp) != NULL) {
        c1 = *cp;
        if (c1 == c)
            *cp = c->next;
        else
            cp = &c1->next;
    }

    /* remove connection associated resources */
    if (c->fd >= 0)
      close(c->fd);
    if (c->udp_fd >= 0)
      close(c->udp_fd);

    av_freep(&c->pb_buffer);
    av_free(c->buffer);
    av_free(c);
    nb_connections--;
}

static void rtsp_reply_header(RTSPContext *c, enum RTSPStatusCode error_number)
{
    const char *str;
    time_t ti;
    struct tm *tm;
    char buf2[32];

    str = RTSP_STATUS_CODE2STRING(error_number);
    //str = "OK";
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
//    avio_printf(c->pb, "\r\n");
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
       //  XXX: cannot do more 
        c->pb = NULL;//  safety 
        return -1;
    }

    printf("cmd = %s \n", cmd);
    //printf("url = %s \n", url);
   // printf("protocol = %s \n", protocol);
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
      // header에 line읽은거 셋팅하는 거인 듯?
      ff_rtsp_parse_line(header, line, NULL, NULL);
      p = p1 + 1;
    }
    /* handle sequence number */
    c->seq = header->seq;
    if (!strcmp(cmd, "DESCRIBE")) {
        printf("DESCRIBE!!!\n");
        rtsp_cmd_describe(c, url);
    }
    else if (!strcmp(cmd, "OPTIONS")) {
        printf("Options! \n");
        rtsp_cmd_options(c, url);
    }
    else if (!strcmp(cmd, "SETUP")) {
        printf("Setup!!!\n");
        rtsp_cmd_setup(c, url, header);
    }
    else if (!strcmp(cmd, "PLAY")) {
        printf("Play!!! \n");
        rtsp_cmd_play(c, url, header);
    }
    else if (!strcmp(cmd, "PAUSE")) {
        printf("PAUSE!!!\n");
        rtsp_cmd_interrupt(c, url, header, 1);
    }
    else if (!strcmp(cmd, "TEARDOWN")) {
        rtsp_cmd_interrupt(c, url, header, 0);
        printf("TEARDOWN!!!\n");
    }
    else {
        rtsp_reply_error(c, RTSP_STATUS_METHOD);
        printf("Error!!");
    }

 the_end:
    printf("parsing end!\n");
    // write rstp reply packet! text 
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

/* RTSP Handle Function */

static void rtsp_cmd_options(RTSPContext *c, const char *url)
{
  rtsp_reply_header(c, RTSP_STATUS_OK);
  avio_printf(c->pb, "RTSP/1.0 %d %s\r\n", RTSP_STATUS_OK, "OK");
  avio_printf(c->pb, "CSeq: %d\r\n", c->seq);
  avio_printf(c->pb, "Public: %s\r\n", "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE");
  //avio_printf(c->pb, "Public: %s\r\n", "OPTIONS, SETUP, TEARDOWN, PLAY, PAUSE");
  avio_printf(c->pb, "\r\n");
}

static void rtsp_cmd_describe(RTSPContext *c, const char *url)
{
  iStream *stream;
  char path1[1024];
  const char *path;
  uint8_t *content;
  int content_length = 0;
  socklen_t len;
  struct sockaddr_in my_addr;

  /* find which URL is asked */
  av_url_split(NULL, 0, NULL, 0, NULL, 0, NULL, path1, sizeof(path1), url);
  int l = strlen(path1);
  if (path1[l-1] == '/') {
    path1[l-1] = '\0';
  }
  path = path1;
  if (*path == '/')
      path++;

  for(stream = first_stream; stream != NULL; stream = stream->next) {
      if (!strcmp(path, stream->name)) {
          goto found;
      }
  }
  /* no stream found */
  rtsp_reply_error(c, RTSP_STATUS_SERVICE); /* XXX: right error ? */
  return;

found:
  /* prepare the media description in SDP format */
  content = av_mallocz(1024);
  /* get the host IP */
  len = sizeof(my_addr);
  getsockname(c->fd, (struct sockaddr *)&my_addr, &len);
  rtsp_reply_header(c, RTSP_STATUS_OK);
  avio_printf(c->pb, "Content-Base: %s/\r\n", url);
  avio_printf(c->pb, "Content-Type: application/sdp\r\n");
  int added_length = 0;
  //printf("stream codec_name = %s, length = %lu\n", stream->codec_name, strlen(stream->codec_name));
  // 여기에 sdp정보 추가 해야 함. 
  content_length = generate_sdp_context(stream, &content);
  printf("generate sdp!! content legnth = %d\n", content_length);
  /*
  if (stream->codec_name && strcmp(stream->codec_name, "hevc") == 0) {
    added_length = strlen("a=rtpmap:96 H265/9000\na=fmpt:96 profile-level-id=UVWXYZ;packetization-mode=1");
    av_strlcatf(content, 2048, "a=rtpmap:96 H265/9000\na=fmpt:96 profile-level-id=UVWXYZ;packetization-mode=1");
  }
  */
  avio_printf(c->pb, "Content-Length: %d\r\n", content_length + added_length);
  avio_printf(c->pb, "\r\n");
  // content added
  avio_write(c->pb, content, content_length + added_length);
  //printf("av free!! \n");
  av_free(content);
  //printf("av free!! end \n");
}

int generate_sdp_context(iStream *stream, unsigned char **buf)
{
  int offset = 0;
  strncpy((char *)*buf, "v=0\r\n", strlen("v=0\r\n"));
  offset += strlen("v=0\r\n");
  strncpy((char *)*buf + offset, "o=- 0 0 IN IP4 172.16.33.222\r\n", strlen("o=- 0 0 IN IP4 172.16.33.222\r\n"));
  offset += strlen("o=- 0 0 IN IP4 172.16.33.222\r\n");
  strncpy((char *)*buf + offset, "s=iStreaming Server\r\n", strlen("s=iStreaming Server\r\n"));
  offset += strlen("s=iStreaming Server\r\n");
  strncpy((char *)*buf + offset, "c=IN IP4 172.16.33.222\r\n", strlen("c=IN IP4 172.16.33.222\r\n"));
  offset += strlen("c=IN IP4 172.16.33.222\r\n");
  strncpy((char *)*buf + offset, "t=0 0\r\n", strlen("t=0 0\r\n"));
  offset += strlen("t=0 0\r\n");
  //strncpy((char *)*buf + offset, "a=range:npt=0-\r\n", strlen("a=range:npt=0-\r\n"));
  //offset += strlen("a=range:npt=0-\r\n");
  char *range = malloc(50); 
  sprintf(range, "%s%d%s", "a=range:npt=0-",stream->idx_hdr->duration, "\r\n");
  printf("range length = %ld, range = %s\n", strlen(range), range);
  strncpy((char *)*buf + offset, range, strlen(range));
  printf("buf = %s", *buf);
  offset += strlen(range);
  free(range);
  strncpy((char *)*buf + offset, "m=video 0 RTP/AVP 33\r\n", strlen("m=video 0 RTP/AVP 96\r\n"));
  offset += strlen("m=video 0 RTP/AVP 33\r\n");
  strncpy((char *)*buf + offset, "a=control:*\r\n", strlen("a=control:*\r\n"));
  offset += strlen("a=control:*\r\n");
  /*
  if (stream->idx_hdr->encoding_format == 0) {
    // 264
    strncpy((char *)*buf + offset, "a=rtpmap:96 H264/9000\r\n", strlen("a=rtpmap:96 H264/9000\r\n"));
    offset += strlen("a=rtpmap:33 H264/9000\r\n");
  } else {
    // 265
    strncpy((char *)*buf + offset, "a=rtpmap:96 H265/9000\r\n", strlen("a=rtpmap:96 H265/9000\r\n"));
    offset += strlen("a=rtpmap:33 H265/9000\r\n");
  }
  strncpy((char *)*buf + offset, "a=fmtp:33 packetization-mode=1;\r\n", strlen("a=fmtp:96 packetization-mode=1;\r\n"));
  offset += strlen("a=fmtp:33 packetization-mode=1;\r\n");
  */
  return offset;
}

static RTSPContext *rtp_new_connection(struct sockaddr_in *from_addr,
                                       iStream *stream, const char *session_id)
{
  printf("rtp_new_connection !! session_id = %s\n", session_id);
  RTSPContext *c = NULL;
  const char *proto_str;

  /* XXX: should output a warning page when coming
     close to the connection limit */
  if (nb_connections >= 100)
      goto fail;

  /* add a new connection */
  c = av_mallocz(sizeof(RTSPContext));
  if (!c)
      goto fail;

  c->fd = -1;
  c->poll_entry = NULL;
  c->from_addr = *from_addr;
  c->buffer_size = IOBUFFER_INIT_SIZE;
  c->buffer = av_malloc(c->buffer_size);
  if (!c->buffer)
      goto fail;
  nb_connections++;
  c->stream = stream;
  c->buffer_ptr = c->buffer;
  c->buffer_end = c->buffer;
  av_strlcpy(c->session_id, session_id, sizeof(c->session_id));
  c->state = HTTPSTATE_READY;
  c->last_packet_sent = false;

  /* protocol is shown in statistics */
  av_strlcpy(c->protocol, "RTP/UDP", sizeof(c->protocol));

  c->next = first_rtsp_ctx;
  first_rtsp_ctx = c;
  return c;
fail:
  if (c) {
      av_free(c->buffer);
      av_free(c);
  }
  return NULL;
}

static int rtp_new_stream(RTSPContext *c, struct sockaddr_in *dest_addr)
{
  char *ipaddr;
  int max_packet_size;

  /* build destination RTP address */
  ipaddr = inet_ntoa(dest_addr->sin_addr);

  printf("rtp/udp case!\n");
  /* RTP/UDP case */
  //create udp socket 
  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd <0 )
  {
    printf("socket udp error!\n ");
    goto fail;
  }

  struct sockaddr_in serveraddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  // 적절한 port찾는 거 추가. 
  serveraddr.sin_port = 0; // 0이면 알아서 사용 가능한 포트로 셋팅!

  if (bind (udp_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
    printf("udp binding error! \n");
    close(udp_fd);
    goto fail;
  }

  struct sockaddr_in sin;
  socklen_t len = sizeof(len);
  if (getsockname(udp_fd, (struct sockaddr *)&sin, &len) != -1) {
    //sucess 
    printf("port number %d\n", ntohs(sin.sin_port)); 
    c->udp_port = ntohs(sin.sin_port);

    // open udp port for rctp control 
    serveraddr.sin_port = c->udp_port + 1;
    int rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(rtcp_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  }

  // udp connect success!
  c->udp_fd = udp_fd;
  c->cur_offset = 0;
  //c->ts_file = fopen(c->stream->filename, "rb");
  return 0;

  fail:
    printf("rtp new stream fail\n");
    return -1;
}

static void rtsp_cmd_play(RTSPContext *c, const char *url, RTSPMessageHeader *h)
{
    RTSPContext *rtp_c;

    rtp_c = find_rtp_session_with_url(url, h->session_id);
    if (!rtp_c) {
      printf("can't find rtp session %s with url %s \n", h->session_id, url);
      rtsp_reply_error(c, RTSP_STATUS_SESSION);
      return;
    }

    rtp_c->start_time = cur_time; // set start time
    // pos * 188이 offset!
    int64_t last_offset = rtp_c->cur_offset;
    printf("cmd play! cur_offset = %lld\n", rtp_c->cur_offset);
    rtp_c->cur_offset = get_closest_iframe_pos(rtp_c->stream->first_idx, rtp_c->cur_offset / 188) * 188; 
    printf("cmd play! after find iframe cur_offset = %lld\n", rtp_c->cur_offset);
    // reset served bytes for restart from pause state
    rtp_c->served_bytes = rtp_c->cur_offset - last_offset;
    printf("cmd play! served_bytes = %lld\n", rtp_c->served_bytes);
    if (rtp_c->buffer_ptr >= rtp_c->buffer_end) {
      printf("no need to reset rtpc->buffer ptr \n");
    }
    rtp_c->state = HTTPSTATE_SEND_DATA;
    /* now everything is OK, so we can send the connection parameters */
    rtsp_reply_header(c, RTSP_STATUS_OK);
    /* session ID */
    avio_printf(c->pb, "Session: %s\r\n", rtp_c->session_id);
    avio_printf(c->pb, "\r\n");
}

static void rtsp_cmd_interrupt(RTSPContext *c, const char *url, RTSPMessageHeader *h, int pause_only)
{
  RTSPContext *rtp_c;

  rtp_c = find_rtp_session_with_url(url, h->session_id);
  if (!rtp_c) {
    rtsp_reply_error(c, RTSP_STATUS_SESSION);
    return;
  }

  if (pause_only) {
    if (rtp_c->state != HTTPSTATE_SEND_DATA) {
      rtsp_reply_error(c, RTSP_STATUS_STATE);
      return;
    }
    rtp_c->state = HTTPSTATE_READY;
   // rtp_c->first_pts = AV_NOPTS_VALUE;
  }

  /* now everything is OK, so we can send the connection parameters */
  rtsp_reply_header(c, RTSP_STATUS_OK);
  /* session ID */
  avio_printf(c->pb, "Session: %s\r\n", rtp_c->session_id);
  avio_printf(c->pb, "\r\n");

  if (!pause_only)
    close_connection(rtp_c);
}

static RTSPTransportField *find_transport(RTSPMessageHeader *h)
{
    RTSPTransportField *th;
    int i;

    for(i=0;i<h->nb_transports;i++) {
        th = &h->transports[i];
        //printf("find transprot!! lower_transprot = %d\n", th->lower_transport);
        if (th->lower_transport == RTSP_LOWER_TRANSPORT_UDP)
            return th;
    }
    return NULL;
}


static void rtsp_cmd_setup(RTSPContext *c, const char *url, RTSPMessageHeader *h)
{
    iStream *stream;
    int stream_index, rtp_port, rtcp_port;
    char buf[1024];
    char path1[1024];
    char *path;
    RTSPContext *rtp_c;
    RTSPTransportField *th;
    struct sockaddr_in dest_addr;
    RTSPActionServerSetup setup;

    /* find which URL is asked */
    av_url_split(NULL, 0, NULL, 0, NULL, 0, NULL, path1, sizeof(path1), url);
    int len = strlen(path1);
    if (path1[len-1] == '/') {
      path1[len-1] = '\0';
    }
    // / 뒤에꺼 없애자! 
    char *removed_path = strrchr(path1, '/');
    if (removed_path != NULL && removed_path != path1)
    {
      printf("removed path != null, will removed str= %s \n", removed_path);
      printf("removed path != null, strlen = %ld \n", removed_path - path1);
      path = path1;
      path[removed_path-path1] = '\0'; 
    } else {
      path = path1;
    }
    if (*path == '/')
        path++;
    printf("rtsp setup! find stream name = %s\n", path);
    /* now check each stream */
    for(stream = first_stream; stream != NULL; stream = stream->next) {
        /* accept aggregate filenames only if single stream */
        if (!strcmp(path, stream->name)) {
          goto found;
        }
    }
    /* no stream found */
    rtsp_reply_error(c, RTSP_STATUS_SERVICE); /* XXX: right error ? */
    return;
 found:

    /* generate session id if needed */
    if (h->session_id[0] == '\0') {
      unsigned random0 = av_lfg_get(&random_state);
      unsigned random1 = av_lfg_get(&random_state);
      snprintf(h->session_id, sizeof(h->session_id), "%08x%08x",
               random0, random1);
    }

    /* find RTP session, and create it if none found */
    rtp_c = find_rtp_session(h->session_id);
    if (!rtp_c) {
      rtp_c = rtp_new_connection(&c->from_addr, stream, h->session_id);
      if (!rtp_c) {
          rtsp_reply_error(c, RTSP_STATUS_BANDWIDTH);
          return;
      }
    }

    /* test if stream is OK (test needed because several SETUP needs
       to be done for a given file) */
    if (rtp_c->stream != stream) {
        rtsp_reply_error(c, RTSP_STATUS_SERVICE);
        return;
    }

    // udp 로 전송 가능한지 체크. 
    th = find_transport(h);
    if (!th) {
      printf("can't do udp transport \n");
      rtsp_reply_error(c, RTSP_STATUS_INTERNAL);
      return;
    }

    /* setup default options */
    setup.transport_option[0] = '\0';
    dest_addr = rtp_c->from_addr;
   // dest_addr.sin_port = th->client_port_min;
    dest_addr.sin_port = htons(th->client_port_min);
   // dest_addr.sin_port = ntohs(th->client_port_min);

    // setup stream 
    // open new rtp/udp socket!
    if (rtp_new_stream(rtp_c, &dest_addr) < 0) {
        rtsp_reply_error(c, RTSP_STATUS_TRANSPORT);
        return;
    }

    rtp_c->to_addr = dest_addr;

    /* now everything is OK, so we can send the connection parameters */
    rtsp_reply_header(c, RTSP_STATUS_OK);
    /* session ID */
    avio_printf(c->pb, "Session: %s\r\n", rtp_c->session_id);

    // rtcp 도 열어야되나? -_-;
    rtp_port = rtp_c->udp_port;
    rtcp_port = rtp_port+1; //  실제로 만들지는 않음..
    avio_printf(c->pb, "Transport: RTP/AVP/UDP;unicast;"
                "client_port=%d-%d;server_port=%d-%d",
                th->client_port_min, th->client_port_max,
                rtp_port, rtcp_port);
    if (setup.transport_option[0] != '\0')
        avio_printf(c->pb, ";%s", setup.transport_option);
        
    avio_printf(c->pb, "\r\n");
    avio_printf(c->pb, "\r\n");
}

static RTSPContext *find_rtp_session(const char *session_id)
{
    RTSPContext *c;

    if (session_id[0] == '\0')
        return NULL;

    for(c = first_rtsp_ctx; c != NULL; c = c->next) {
        if (!strcmp(c->session_id, session_id))
            return c;
    }
    return NULL;
}

static RTSPContext *find_rtp_session_with_url(const char *url, const char *session_id)
{
    RTSPContext *rtp_c;
    char path1[1024];
    const char *path;
    char buf[1024];
    int s, len;

    rtp_c = find_rtp_session(session_id);
    if (!rtp_c)
        return NULL;

    /* find which URL is asked */
    av_url_split(NULL, 0, NULL, 0, NULL, 0, NULL, path1, sizeof(path1), url);
    len = strlen(path1);
    if (path1[len-1] == '/') {
      path1[len-1] = '\0';
    }
    path = path1;
    if (*path == '/')
        path++;
    if(!strcmp(path, rtp_c->stream->name)) return rtp_c;

    return NULL;
}

#define RTP_HEADER_SIZE 12 //csrc 없을 때..ㅋㅋ
#define RTP_PACKET_SIZE 12 + 188*7
static int http_prepare_data(RTSPContext *c)
{
  // prepare rtp data
  // Generate RTP Packet
  // write rtp header and parse mpeg-ts file to make rtp packet
  if (c->stream) {
    c->pb_buffer = av_mallocz(RTP_PACKET_SIZE);
    if (!c->pb_buffer) {
      // malloc error 
      perror("malloc error! when rtp packet generation !\n");
      return -1;
    }

    iStream *stream = c->stream; 
    rtp_hdr_t *rtp_hdr = calloc(sizeof(*rtp_hdr), 1);
    rtp_hdr->version = 2;
    rtp_hdr->x = 0; // header extend length = 0. don't set
    rtp_hdr->cc = 0; // csrc length = 0  don't set
    rtp_hdr->m = 0; // last packet일 경우에는 0아님 
    rtp_hdr->pt = 33; // mpege-ts 형식은 33
    rtp_hdr->seq = c->cur_seq++; // seq 계속 올라갸야함. 
    rtp_hdr->ssrc = av_lfg_get(&random_state);
    unsigned int bit_rate = stream->bit_rate;
    int64_t offset = c->cur_offset;
    long long int ts_offset = ((double)c->cur_offset * 8.0  * 90000.0) / ((double)bit_rate * 1000.0);
    rtp_hdr->ts = ts_offset;
    // set header
    memcpy(c->pb_buffer, rtp_hdr, RTP_HEADER_SIZE);
    free(rtp_hdr); // dealloc memory.

    FILE *fr = fopen(stream->filename, "rb");
    if (fr < 0)
    {
      perror("fopen error!\n");
      return -1;
    }
    // read from file 
    if(fseek(fr, offset, SEEK_SET) == -1) {
      perror("fseek error!\n");
      return -1;
    }
    // file의 마지막 ts packet 범위 안인지 체크. 
    unsigned int cur_pos = offset / 188;
    unsigned int last_pos = stream->total_length;

    if (last_pos <= 1) {
      fclose(fr);
      return 0;
    }

    c->buffer_ptr = c->pb_buffer;
    //printf("http prepare data! cur_pos = %u last_pos = %u, bit_rate = %u \n", cur_pos, last_pos, stream->bit_rate);
    if (cur_pos + 7 < last_pos) {
      int r_size = 188*7;
      unsigned char buf[r_size];
      fread(buf, 1, r_size, fr);
      memcpy(c->pb_buffer+RTP_HEADER_SIZE, buf, r_size);
      c->buffer_end = c->pb_buffer + r_size + RTP_HEADER_SIZE;
    } else {
      int rest_bytes = 188 * (last_pos - cur_pos);
      unsigned char buf[rest_bytes];
      fread(buf, 1, rest_bytes, fr);
      memcpy(c->pb_buffer+RTP_HEADER_SIZE, buf, rest_bytes);
      c->buffer_end = c->pb_buffer + rest_bytes + 12;
    }
    fclose(fr);
  } else {
    perror("rtsp context doesn't have ts file!!! \n");
    return -1;
  }
  
  return 1;
}

static int rtp_send_data(RTSPContext *c)
{
  return 1;
}

static int http_send_data(RTSPContext *c)
{
    int len, ret;

    for(;;) {
      if (c->buffer_ptr >= c->buffer_end) {
        //printf("prepare data!! \n");
        ret = http_prepare_data(c);
        if (ret < 0)
            return -1;
        else if (ret != 0)
            /* state change requested */
            break;
      } else {
        /* RTP data output */
        len = c->buffer_end - c->buffer_ptr;
        //printf("send data! len = %d offset_time = %lld\n", len, (cur_time - c->start_time) / 1000);
        if (len < 4) {
            /* fail safe - should never happen */
        fail1:
            c->buffer_ptr = c->buffer_end;
            return 0;
        }

        cur_time = av_gettime() / 1000;
        // data rate 계산해서, 보낸 데이터 양이 byte stream보다 크면 보내지 않음
        int64_t offset_time = (cur_time - c->start_time); // ms 단위..
        unsigned int bit_rate = c->stream->idx_hdr->bit_rate; // kbps 임.. 
        if (c->served_bytes * 8 > offset_time * bit_rate) {
          // bitrate 맞추기 위해. ;
          //dump_iIndexHeader(c->stream->idx_hdr);
          //printf("data rate too fast! bit_rate = %u, served_bytes = %lld, offset_time = %lld \n", bit_rate, served_bytes, offset_time);
          return 0;
        }

        /* send RTP packet directly in UDP */
        if (!c->last_packet_sent) {
          //printf("send rtp packet using udp! pb_buffer size = %ld \n", c->buffer_end - c->buffer_ptr);
          len = sendto(c->udp_fd, c->pb_buffer, c->buffer_end - c->buffer_ptr, 0, (struct sockaddr *)&c->to_addr, sizeof(c->to_addr));
          if (len < 0) 
          {
            perror("rtp pakcet send error! \n");
            //send fail 
            free(c->pb_buffer);
            return -1;
          }
          if (offset_time % 1000 == 0)
            printf("served bytes report! served_bytes =  %lldkb, time_offset = %lldms \n", c->served_bytes / 1000, offset_time);
          c->buffer_ptr += len;
          c->served_bytes += len; // pause 처리를 위해,  served_bytes를 가지고 있어야 함.
          c->cur_offset += len - 12; // rtp header size remove
          int cur_pos = c->cur_offset / 188;
          if (cur_pos >= c->stream->total_length) {
            printf("packet end!! time = %lld\n", offset_time);
            c->last_packet_sent = true;
            close_connection(c);
          }
          if (c->buffer_ptr >= c->buffer_end)
            av_free(c->pb_buffer);
        }
       /* here we continue as we can send several packets per 10 ms slot */
      }
    } /* for(;;) */
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sigact = { { 0 } };
    int ret = 0;

    config_filename = av_strdup("/etc/ffserver.conf");
    av_lfg_init(&random_state, av_get_random_seed());

    if ((ret = parse_ffconfig(config_filename)) < 0) {
        fprintf(stderr, "Error reading configuration file '%s': %s\n",
                config_filename, av_err2str(ret));
        exit(1);
    }
    av_freep(&config_filename);
    // set logfile
    logfile = stdout;

    build_file_streams();

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
