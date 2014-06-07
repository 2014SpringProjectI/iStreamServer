#include <stdio.h>
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
#include "libavformat/avformat.h"
#include "libavformat/rtpdec.h"
#include "libavformat/rtsp.h"
#include "libavformat/rtspcodes.h"
#include "libavformat/avio_internal.h"
#include "libavformat/internal.h"
#include "libavformat/url.h"
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/lfg.h"
#include "libavutil/dict.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mathematics.h"
#include "libavutil/pixdesc.h"
#include "libavutil/random_seed.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/mem.h"

#define HTTP_REQUEST_TIMEOUT (15 * 1000)
#define RTSP_REQUEST_TIMEOUT (3600 * 24 * 1000)
#define IOBUFFER_INIT_SIZE 8192

//static const OptionDef options[];

enum HTTPState {
    HTTPSTATE_WAIT_REQUEST,
    HTTPSTATE_SEND_HEADER,
    HTTPSTATE_SEND_DATA_HEADER,
    HTTPSTATE_SEND_DATA,          /* sending TCP or UDP data */
    HTTPSTATE_SEND_DATA_TRAILER,
    HTTPSTATE_RECEIVE_DATA,
    HTTPSTATE_WAIT_FEED,          /* wait for data from the feed */
    HTTPSTATE_READY,
    RTSPSTATE_WAIT_REQUEST,
    RTSPSTATE_SEND_REPLY,
    RTSPSTATE_SEND_PACKET,
};

static const char *http_state[] = {
    "HTTP_WAIT_REQUEST",
    "HTTP_SEND_HEADER",
    "SEND_DATA_HEADER",
    "SEND_DATA",
    "SEND_DATA_TRAILER",
    "RECEIVE_DATA",
    "WAIT_FEED",
    "READY",
    "RTSP_WAIT_REQUEST",
    "RTSP_SEND_REPLY",
    "RTSP_SEND_PACKET",
};

typedef struct RTSPActionServerSetup {
    uint32_t ipaddr;
    char transport_option[512];
} RTSPActionServerSetup;

typedef struct {
    int64_t count1, count2;
    int64_t time1, time2;
} DataRateData;

typedef struct FeedData {
    long long data_count;
    float avg_frame_size;   /* frame size averaged over last frames with exponential mean */
} FeedData;


/* context associated with one connection */
#define MAX_STREAMS 20
typedef struct RTSPContext {
    enum HTTPState state;
    int fd; /* socket file descriptor */
    struct sockaddr_in from_addr; /* origin */
    struct pollfd *poll_entry; /* used when polling */
    int64_t timeout;
    uint8_t *buffer_ptr, *buffer_end;
    int http_error;
    int post;
    int chunked_encoding;
    int chunk_size;               /* 0 if it needs to be read */
    struct RTSPContext *next;
    int got_key_frame; /* stream 0 => 1, stream 1 => 2, stream 2=> 4 */
    int64_t data_count;
    /* input format handling */
    AVFormatContext *fmt_in;
    int64_t start_time;            /* In milliseconds - this wraps fairly often */
    int64_t first_pts;            /* initial pts value */
    int64_t cur_pts;             /* current pts value from the stream in us */
    int64_t cur_frame_duration;  /* duration of the current frame in us */
    int cur_frame_bytes;       /* output frame size, needed to compute
                                  the time at which we send each
                                  packet */
    int pts_stream_index;        /* stream we choose as clock reference */
    int64_t cur_clock;           /* current clock reference value in us */
    /* output format handling */
    struct FFStream *stream;
    /* -1 is invalid stream */
    int feed_streams[MAX_STREAMS]; /* index of streams in the feed */
    int switch_feed_streams[MAX_STREAMS]; /* index of streams in the feed */
    int switch_pending;
    AVFormatContext fmt_ctx; /* instance of FFStream for one user */
    int last_packet_sent; /* true if last data packet was sent */
    int suppress_log;
    DataRateData datarate;
    int wmp_client_id;
    char protocol[16];
    char method[16];
    char url[128];
    int buffer_size;
    uint8_t *buffer;
    int is_packetized; /* if true, the stream is packetized */
    int packet_stream_index; /* current stream for output in state machine */

    /* RTSP state specific */
    uint8_t *pb_buffer; /* XXX: use that in all the code */
    AVIOContext *pb;
    int seq; /* RTSP sequence number */

    /* RTP state specific */
    enum RTSPLowerTransport rtp_protocol;
    char session_id[32]; /* session id */
    AVFormatContext *rtp_ctx[MAX_STREAMS];

    /* RTP/UDP specific */
    URLContext *rtp_handles[MAX_STREAMS];

    /* RTP/TCP specific */
    struct RTSPContext *rtsp_c;
    uint8_t *packet_buffer, *packet_buffer_ptr, *packet_buffer_end;
} RTSPContext;

enum StreamType {
    STREAM_TYPE_LIVE,
    STREAM_TYPE_STATUS,
    STREAM_TYPE_REDIRECT,
};

enum IPAddressAction {
    IP_ALLOW = 1,
    IP_DENY,
};

typedef struct IPAddressACL {
    struct IPAddressACL *next;
    enum IPAddressAction action;
    /* These are in host order */
    struct in_addr first;
    struct in_addr last;
} IPAddressACL;

/* description of each stream of the ffserver.conf file */
typedef struct FFStream {
    enum StreamType stream_type;
    char filename[1024];     /* stream filename */
    struct FFStream *feed;   /* feed we are using (can be null if */
    AVDictionary *in_opts;   /* input parameters */
    AVDictionary *metadata;  /* metadata to set on the stream */
    AVInputFormat *ifmt;       /* if non NULL, force input format */
    AVOutputFormat *fmt;
    IPAddressACL *acl;
    char dynamic_acl[1024];
    int nb_streams;
    int prebuffer;      /* Number of milliseconds early to start */
    int64_t max_time;      /* Number of milliseconds to run */
    int send_on_key;
    AVStream *streams[MAX_STREAMS];
    int feed_streams[MAX_STREAMS]; /* index of streams in the feed */
    char feed_filename[1024]; /* file name of the feed storage, or
                                 input file name for a stream */
    pid_t pid;  /* Of ffmpeg process */
    time_t pid_start;  /* Of ffmpeg process */
    char **child_argv;
    struct FFStream *next;
    unsigned bandwidth; /* bandwidth, in kbits/s */
    /* RTSP options */
    char *rtsp_option;
    /* multicast specific */
    int is_multicast;
    struct in_addr multicast_ip;
    int multicast_port; /* first port used for multicast */
    int multicast_ttl;
    int loop; /* if true, send the stream in loops (only meaningful if file) */
    int64_t bytes_served;
    int is_feed;         /* true if it is a feed */
} FFStream;

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

/* SDP handling */
static int prepare_sdp_description(FFStream *stream, uint8_t **pbuffer,
                                   struct in_addr my_ip);

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
static FFStream *first_stream; /* contains all streams, including feeds */
static AVLFG random_state;

static FILE *logfile = NULL;

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

static void http_av_log(void *ptr, int level, const char *fmt, va_list vargs)
{
    static int print_prefix = 1;
    AVClass *avc = ptr ? *(AVClass**)ptr : NULL;
    if (level > av_log_get_level())
        return;
    if (print_prefix && avc)
        http_log("[%s @ %p]", avc->item_name(ptr), ptr);
    print_prefix = strstr(fmt, "\n") != NULL;
    http_vlog(fmt, vargs);
}

static void log_connection(RTSPContext *c)
{
    if (c->suppress_log)
        return;

    http_log("%s - - [%s] \"%s %s\" %d %"PRId64"\n",
             inet_ntoa(c->from_addr.sin_addr), c->method, c->url,
             c->protocol, (c->http_error ? c->http_error : 200), c->data_count);
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

static AVOutputFormat *ffserver_guess_format(const char *short_name, const char *filename, const char *mime_type)
{
    AVOutputFormat *fmt = av_guess_format(short_name, filename, mime_type);

    if (fmt) {
        AVOutputFormat *stream_fmt;
        char stream_format_name[64];

        snprintf(stream_format_name, sizeof(stream_format_name), "%s_stream", fmt->name);
        stream_fmt = av_guess_format(stream_format_name, NULL, NULL);

        if (stream_fmt)
            fmt = stream_fmt;
    }

    return fmt;
}

static int parse_ffconfig(const char *filename)
{
    FILE *f;
    char line[1024];
    char cmd[64];
    char arg[1024], arg2[1024];
    const char *p;
    int val, errors, warnings, line_num;
    FFStream **last_stream, *stream, *redirect;
    AVCodecContext audio_enc, video_enc;
    enum AVCodecID audio_id, video_id;
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
    audio_id = AV_CODEC_ID_NONE;
    video_id = AV_CODEC_ID_NONE;
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
        //printf("cmd = %s \n", cmd);

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
        } else if (!av_strcasecmp(cmd, "MaxHTTPConnections")) {
            get_arg(arg, sizeof(arg), &p);
            val = atoi(arg);
            if (val < 1 || val > 65536) {
                ERROR("Invalid MaxHTTPConnections: %s\n", arg);
            }
            nb_max_http_connections = val;
        } else if (!av_strcasecmp(cmd, "MaxClients")) {
            get_arg(arg, sizeof(arg), &p);
            val = atoi(arg);
            if (val < 1 || val > nb_max_http_connections) {
                ERROR("Invalid MaxClients: %s\n", arg);
            } else {
                nb_max_connections = val;
            }
        } else if (!av_strcasecmp(cmd, "MaxBandwidth")) {
            int64_t llval;
            get_arg(arg, sizeof(arg), &p);
            llval = strtoll(arg, NULL, 10);
            if (llval < 10 || llval > 10000000) {
                ERROR("Invalid MaxBandwidth: %s\n", arg);
            } else
                max_bandwidth = llval;
        } else if (!av_strcasecmp(cmd, "File") || !av_strcasecmp(cmd, "ReadOnlyFile")) {
            if (stream) {
                get_arg(stream->feed_filename, sizeof(stream->feed_filename), &p);
            }
        }  else if (!av_strcasecmp(cmd, "<Stream")) {
            /*********************************************/
            /* Stream related options */
            char *q;
            if (stream) {
                ERROR("Already in a tag\n");
            } else {
                FFStream *s;
                stream = av_mallocz(sizeof(FFStream));
                if (!stream) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
                get_arg(stream->filename, sizeof(stream->filename), &p);
                q = strrchr(stream->filename, '>');
                if (q)
                    *q = '\0';

                printf("stream filename = %s \n", stream->filename);
                for (s = first_stream; s; s = s->next) {
                    if (!strcmp(stream->filename, s->filename)) {
                        ERROR("Stream '%s' already registered\n", s->filename);
                    }
                }

                stream->fmt = ffserver_guess_format(NULL, stream->filename, NULL);
                avcodec_get_context_defaults3(&video_enc, NULL);
                avcodec_get_context_defaults3(&audio_enc, NULL);

                audio_id = AV_CODEC_ID_NONE;
                video_id = AV_CODEC_ID_NONE;
                if (stream->fmt) {
                  printf("steam -> fmt is exist \n");
                    audio_id = stream->fmt->audio_codec;
                    video_id = stream->fmt->video_codec;
                }
                *last_stream = stream;
                last_stream = &stream->next;
            }
        } else if (!av_strcasecmp(cmd, "Format")) {
            get_arg(arg, sizeof(arg), &p);
            if (stream) {
                if (!strcmp(arg, "status")) {
                    stream->stream_type = STREAM_TYPE_STATUS;
                    stream->fmt = NULL;
                } else {
                    stream->stream_type = STREAM_TYPE_LIVE;
                    /* JPEG cannot be used here, so use single frame MJPEG */
                    if (!strcmp(arg, "jpeg"))
                        strcpy(arg, "mjpeg");
                    stream->fmt = ffserver_guess_format(arg, NULL, NULL);
                    if (!stream->fmt) {
                        ERROR("Unknown Format: %s\n", arg);
                    }
                }
                if (stream->fmt) {
                    audio_id = stream->fmt->audio_codec;
                    video_id = stream->fmt->video_codec;
                }
            }
        } else if (!av_strcasecmp(cmd, "Debug")) {
            if (stream) {
                get_arg(arg, sizeof(arg), &p);
                video_enc.debug = strtol(arg,0,0);
            }
        } else if (!av_strcasecmp(cmd, "RTSPOption")) {
            get_arg(arg, sizeof(arg), &p);
            if (stream) {
                av_freep(&stream->rtsp_option);
                stream->rtsp_option = av_strdup(arg);
            }
        } else if (!av_strcasecmp(cmd, "MulticastAddress")) {
            get_arg(arg, sizeof(arg), &p);
            if (stream) {
                if (resolve_host(&stream->multicast_ip, arg) != 0) {
                    ERROR("Invalid host/IP address: %s\n", arg);
                }
                stream->is_multicast = 1;
                stream->loop = 1; /* default is looping */
            }
        } else if (!av_strcasecmp(cmd, "MulticastPort")) {
            get_arg(arg, sizeof(arg), &p);
            if (stream)
                stream->multicast_port = atoi(arg);
        } else if (!av_strcasecmp(cmd, "MulticastTTL")) {
            get_arg(arg, sizeof(arg), &p);
            if (stream)
                stream->multicast_ttl = atoi(arg);
        } else if (!av_strcasecmp(cmd, "</Stream>")) {
            if (!stream) {
                ERROR("No corresponding <Stream> for </Stream>\n");
            } else {
              /*
                if (stream->fmt && strcmp(stream->fmt->name, "ffm") != 0) {
                    if (audio_id != AV_CODEC_ID_NONE) {
                        audio_enc.codec_type = AVMEDIA_TYPE_AUDIO;
                        audio_enc.codec_id = audio_id;
                        add_codec(stream, &audio_enc);
                    }
                    if (video_id != AV_CODEC_ID_NONE) {
                        video_enc.codec_type = AVMEDIA_TYPE_VIDEO;
                        video_enc.codec_id = video_id;
                        add_codec(stream, &video_enc);
                    }
                }
                */
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
        //http_log("start event loop.\n");
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
    AVFormatContext *ctx;
    URLContext *h;
    AVStream *st;

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
    if (c->fmt_in) {
        // close each frame parser
        for(i=0;i<c->fmt_in->nb_streams;i++) {
            st = c->fmt_in->streams[i];
            if (st->codec->codec)
                avcodec_close(st->codec);
        }
        avformat_close_input(&c->fmt_in);
    }

    /* free RTP output streams if any  */
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
            c->data_count += len;
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
        if (http_send_data(c) < 0)
            return -1;
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
            printf("send success!! len = %d \n", len);
            c->buffer_ptr += len;
            c->data_count += len;
            if (c->buffer_ptr >= c->buffer_end) {
                /* all the buffer was sent : wait for a new request */
                //goto close_connection;
                av_freep(&c->pb_buffer);
                start_wait_request(c, 1);
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

static int extract_rates(char *rates, int ratelen, const char *request)
{
    const char *p;

    for (p = request; *p && *p != '\r' && *p != '\n'; ) {
        if (av_strncasecmp(p, "Pragma:", 7) == 0) {
            const char *q = p + 7;

            while (*q && *q != '\n' && av_isspace(*q))
                q++;

            if (av_strncasecmp(q, "stream-switch-entry=", 20) == 0) {
                int stream_no;
                int rate_no;

                q += 20;

                memset(rates, 0xff, ratelen);

                while (1) {
                    while (*q && *q != '\n' && *q != ':')
                        q++;

                    if (sscanf(q, ":%d:%d", &stream_no, &rate_no) != 2)
                        break;

                    stream_no--;
                    if (stream_no < ratelen && stream_no >= 0)
                        rates[stream_no] = rate_no;

                    while (*q && *q != '\n' && !av_isspace(*q))
                        q++;
                }

                return 1;
            }
        }
        p = strchr(p, '\n');
        if (!p)
            break;

        p++;
    }

    return 0;
}

static int find_stream_in_feed(FFStream *feed, AVCodecContext *codec, int bit_rate)
{
    int i;
    int best_bitrate = 100000000;
    int best = -1;

    for (i = 0; i < feed->nb_streams; i++) {
        AVCodecContext *feed_codec = feed->streams[i]->codec;

        if (feed_codec->codec_id != codec->codec_id ||
            feed_codec->sample_rate != codec->sample_rate ||
            feed_codec->width != codec->width ||
            feed_codec->height != codec->height)
            continue;

        /* Potential stream */

        /* We want the fastest stream less than bit_rate, or the slowest
         * faster than bit_rate
         */

        if (feed_codec->bit_rate <= bit_rate) {
            if (best_bitrate > bit_rate || feed_codec->bit_rate > best_bitrate) {
                best_bitrate = feed_codec->bit_rate;
                best = i;
            }
        } else {
            if (feed_codec->bit_rate < best_bitrate) {
                best_bitrate = feed_codec->bit_rate;
                best = i;
            }
        }
    }

    return best;
}

static int modify_current_stream(RTSPContext *c, char *rates)
{
    int i;
    FFStream *req = c->stream;
    int action_required = 0;

    /* Not much we can do for a feed */
    if (!req->feed)
        return 0;

    for (i = 0; i < req->nb_streams; i++) {
        AVCodecContext *codec = req->streams[i]->codec;

        switch(rates[i]) {
            case 0:
                c->switch_feed_streams[i] = req->feed_streams[i];
                break;
            case 1:
                c->switch_feed_streams[i] = find_stream_in_feed(req->feed, codec, codec->bit_rate / 2);
                break;
            case 2:
                /* Wants off or slow */
                c->switch_feed_streams[i] = find_stream_in_feed(req->feed, codec, codec->bit_rate / 4);
#ifdef WANTS_OFF
                /* This doesn't work well when it turns off the only stream! */
                c->switch_feed_streams[i] = -2;
                c->feed_streams[i] = -2;
#endif
                break;
        }

        if (c->switch_feed_streams[i] >= 0 && c->switch_feed_streams[i] != c->feed_streams[i])
            action_required = 1;
    }

    return action_required;
}

static void skip_spaces(const char **pp)
{
    const char *p;
    p = *pp;
    while (*p == ' ' || *p == '\t')
        p++;
    *pp = p;
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

static void parse_acl_row(FFStream *stream, FFStream* feed, IPAddressACL *ext_acl,
                         const char *p, const char *filename, int line_num)
{
    char arg[1024];
    IPAddressACL acl;
    int errors = 0;

    get_arg(arg, sizeof(arg), &p);
    if (av_strcasecmp(arg, "allow") == 0)
        acl.action = IP_ALLOW;
    else if (av_strcasecmp(arg, "deny") == 0)
        acl.action = IP_DENY;
    else {
        fprintf(stderr, "%s:%d: ACL action '%s' is not ALLOW or DENY\n",
                filename, line_num, arg);
        errors++;
    }

    get_arg(arg, sizeof(arg), &p);

    if (resolve_host(&acl.first, arg) != 0) {
        fprintf(stderr, "%s:%d: ACL refers to invalid host or IP address '%s'\n",
                filename, line_num, arg);
        errors++;
    } else
        acl.last = acl.first;

    get_arg(arg, sizeof(arg), &p);

    if (arg[0]) {
        if (resolve_host(&acl.last, arg) != 0) {
            fprintf(stderr, "%s:%d: ACL refers to invalid host or IP address '%s'\n",
                    filename, line_num, arg);
            errors++;
        }
    }

    if (!errors) {
        IPAddressACL *nacl = av_mallocz(sizeof(*nacl));
        IPAddressACL **naclp = 0;

        acl.next = 0;
        *nacl = acl;

        if (stream)
            naclp = &stream->acl;
        else if (feed)
            naclp = &feed->acl;
        else if (ext_acl)
            naclp = &ext_acl;
        else {
            fprintf(stderr, "%s:%d: ACL found not in <stream> or <feed>\n",
                    filename, line_num);
            errors++;
        }

        if (naclp) {
            while (*naclp)
                naclp = &(*naclp)->next;

            *naclp = nacl;
        }
    }
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

/* return the server clock (in us) */
static int64_t get_server_clock(RTSPContext *c)
{
    /* compute current pts value from system time */
    return (cur_time - c->start_time) * 1000;
}

/* return the estimated time at which the current packet must be sent
   (in us) */
static int64_t get_packet_send_clock(RTSPContext *c)
{
    int bytes_left, bytes_sent, frame_bytes;

    frame_bytes = c->cur_frame_bytes;
    if (frame_bytes <= 0)
        return c->cur_pts;
    else {
        bytes_left = c->buffer_end - c->buffer_ptr;
        bytes_sent = frame_bytes - bytes_left;
        return c->cur_pts + (c->cur_frame_duration * bytes_sent) / frame_bytes;
    }
}

// in libavformat/rtsp.c
/*
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

*/

/*
void ff_rtsp_parse_line(RTSPMessageHeader *reply, const char *buf,
                        RTSPState *rt, const char *method)
{
    const char *p;

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
*/

static IPAddressACL* parse_dynamic_acl(FFStream *stream, RTSPContext *c)
{
    FILE* f;
    char line[1024];
    char  cmd[1024];
    IPAddressACL *acl = NULL;
    int line_num = 0;
    const char *p;

    f = fopen(stream->dynamic_acl, "r");
    if (!f) {
        perror(stream->dynamic_acl);
        return NULL;
    }

    acl = av_mallocz(sizeof(IPAddressACL));

    /* Build ACL */
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

        if (!av_strcasecmp(cmd, "ACL"))
            parse_acl_row(NULL, NULL, acl, p, stream->dynamic_acl, line_num);
    }
    fclose(f);
    return acl;
}

static void free_acl_list(IPAddressACL *in_acl)
{
    IPAddressACL *pacl,*pacl2;

    pacl = in_acl;
    while(pacl) {
        pacl2 = pacl;
        pacl = pacl->next;
        av_freep(pacl2);
    }
}

static int validate_acl_list(IPAddressACL *in_acl, RTSPContext *c)
{
    enum IPAddressAction last_action = IP_DENY;
    IPAddressACL *acl;
    struct in_addr *src = &c->from_addr.sin_addr;
    unsigned long src_addr = src->s_addr;

    for (acl = in_acl; acl; acl = acl->next) {
        if (src_addr >= acl->first.s_addr && src_addr <= acl->last.s_addr)
            return (acl->action == IP_ALLOW) ? 1 : 0;
        last_action = acl->action;
    }

    /* Nothing matched, so return not the last action */
    return (last_action == IP_DENY) ? 1 : 0;
}

static int validate_acl(FFStream *stream, RTSPContext *c)
{
    int ret = 0;
    IPAddressACL *acl;


    /* if stream->acl is null validate_acl_list will return 1 */
    ret = validate_acl_list(stream->acl, c);

    if (stream->dynamic_acl[0]) {
        acl = parse_dynamic_acl(stream, c);

        ret = validate_acl_list(acl, c);

        free_acl_list(acl);
    }

    return ret;
}

static void compute_real_filename(char *filename, int max_size)
{
    char file1[1024];
    char file2[1024];
    char *p;
    FFStream *stream;

    /* compute filename by matching without the file extensions */
    av_strlcpy(file1, filename, sizeof(file1));
    p = strrchr(file1, '.');
    if (p)
        *p = '\0';
    for(stream = first_stream; stream != NULL; stream = stream->next) {
        av_strlcpy(file2, stream->filename, sizeof(file2));
        p = strrchr(file2, '.');
        if (p)
            *p = '\0';
        if (!strcmp(file1, file2)) {
            av_strlcpy(filename, stream->filename, max_size);
            break;
        }
    }
}

enum RedirType {
    REDIR_NONE,
    REDIR_ASX,
    REDIR_RAM,
    REDIR_ASF,
    REDIR_RTSP,
    REDIR_SDP,
};

static int open_input_stream(RTSPContext *c, const char *info) {
    char buf[128];
    char input_filename[1024];
    AVFormatContext *s = NULL;
    int buf_size, i, ret;
    int64_t stream_pos;

    strcpy(input_filename, c->stream->feed_filename);
    buf_size = 0;
    /* compute position (relative time) */
    if (av_find_info_tag(buf, sizeof(buf), "date", info)) {
        if ((ret = av_parse_time(&stream_pos, buf, 1)) < 0) {
            http_log("Invalid date specification '%s' for stream\n", buf);
            return ret;
        }
    } else
        stream_pos = 0;

    if (!input_filename[0]) {
        http_log("No filename was specified for stream\n");
        return AVERROR(EINVAL);
    }

    /* open stream */
    if ((ret = avformat_open_input(&s, input_filename, c->stream->ifmt, &c->stream->in_opts)) < 0) {
        http_log("Could not open input '%s': %s\n", input_filename, av_err2str(ret));
        return ret;
    }

    /* set buffer size */
    if (buf_size > 0) ffio_set_buf_size(s->pb, buf_size);

    s->flags |= AVFMT_FLAG_GENPTS;
    c->fmt_in = s;
    if (strcmp(s->iformat->name, "ffm") &&
        (ret = avformat_find_stream_info(c->fmt_in, NULL)) < 0) {
        http_log("Could not find stream info for input '%s'\n", input_filename);
        avformat_close_input(&s);
        return ret;
    }

    /* choose stream as clock source (we favor the video stream if
     * present) for packet sending */
    c->pts_stream_index = 0;
    for(i=0;i<c->stream->nb_streams;i++) {
        if (c->pts_stream_index == 0 &&
            c->stream->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO) {
            c->pts_stream_index = i;
        }
    }

    if (c->fmt_in->iformat->read_seek)
        av_seek_frame(c->fmt_in, -1, stream_pos, 0);
    /* set the start time (needed for maxtime and RTP packet timing) */
    c->start_time = cur_time;
    c->first_pts = AV_NOPTS_VALUE;
    return 0;
}

static void rtsp_cmd_options(RTSPContext *c, const char *url)
{
    rtsp_reply_header(c, RTSP_STATUS_OK);
    avio_printf(c->pb, "RTSP/1.0 %d %s\r\n", RTSP_STATUS_OK, "OK");
    avio_printf(c->pb, "CSeq: %d\r\n", c->seq);
    avio_printf(c->pb, "Public: %s\r\n", "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE");
    avio_printf(c->pb, "\r\n");
}

static void rtsp_cmd_describe(RTSPContext *c, const char *url)
{
    FFStream *stream;
    char path1[1024];
    const char *path;
    uint8_t *content;
    int content_length;
    socklen_t len;
    struct sockaddr_in my_addr;

    /* find which URL is asked */
    av_url_split(NULL, 0, NULL, 0, NULL, 0, NULL, path1, sizeof(path1), url);
    path = path1;
    if (*path == '/')
        path++;

    for(stream = first_stream; stream != NULL; stream = stream->next) {
        if (!stream->is_feed &&
            stream->fmt && !strcmp(stream->fmt->name, "rtp") &&
            !strcmp(path, stream->filename)) {
            goto found;
        }
    }
    /* no stream found */
    rtsp_reply_error(c, RTSP_STATUS_SERVICE); /* XXX: right error ? */
    return;

 found:
    /* prepare the media description in SDP format */

    /* get the host IP */
    len = sizeof(my_addr);
    getsockname(c->fd, (struct sockaddr *)&my_addr, &len);
    content_length = prepare_sdp_description(stream, &content, my_addr.sin_addr);
    if (content_length < 0) {
        rtsp_reply_error(c, RTSP_STATUS_INTERNAL);
        return;
    }
    rtsp_reply_header(c, RTSP_STATUS_OK);
    avio_printf(c->pb, "Content-Base: %s/\r\n", url);
    avio_printf(c->pb, "Content-Type: application/sdp\r\n");
    avio_printf(c->pb, "Content-Length: %d\r\n", content_length);
    avio_printf(c->pb, "\r\n");
    avio_write(c->pb, content, content_length);
    av_free(content);
}

static RTSPContext *find_rtp_session(const char *session_id)
{
    RTSPContext *c;

    if (session_id[0] == '\0')
        return NULL;

    for(c = first_http_ctx; c != NULL; c = c->next) {
        if (!strcmp(c->session_id, session_id))
            return c;
    }
    return NULL;
}

static RTSPTransportField *find_transport(RTSPMessageHeader *h, enum RTSPLowerTransport lower_transport)
{
    RTSPTransportField *th;
    int i;

    for(i=0;i<h->nb_transports;i++) {
        th = &h->transports[i];
        if (th->lower_transport == lower_transport)
            return th;
    }
    return NULL;
}

static RTSPContext *rtp_new_connection(struct sockaddr_in *from_addr,
                                       FFStream *stream, const char *session_id,
                                       enum RTSPLowerTransport rtp_protocol)
{
    RTSPContext *c = NULL;
    const char *proto_str;

    /* XXX: should output a warning page when coming
       close to the connection limit */
    if (nb_connections >= nb_max_connections)
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
    av_strlcpy(c->session_id, session_id, sizeof(c->session_id));
    c->state = HTTPSTATE_READY;
    c->is_packetized = 1;
    c->rtp_protocol = rtp_protocol;

    /* protocol is shown in statistics */
    switch(c->rtp_protocol) {
    case RTSP_LOWER_TRANSPORT_UDP_MULTICAST:
        proto_str = "MCAST";
        break;
    case RTSP_LOWER_TRANSPORT_UDP:
        proto_str = "UDP";
        break;
    case RTSP_LOWER_TRANSPORT_TCP:
        proto_str = "TCP";
        break;
    default:
        proto_str = "???";
        break;
    }
    av_strlcpy(c->protocol, "RTP/", sizeof(c->protocol));
    av_strlcat(c->protocol, proto_str, sizeof(c->protocol));

    current_bandwidth += stream->bandwidth;

    c->next = first_http_ctx;
    first_http_ctx = c;
    return c;

 fail:
    if (c) {
        av_free(c->buffer);
        av_free(c);
    }
    return NULL;
}


/* add a new RTP stream in an RTP connection (used in RTSP SETUP
   command). If RTP/TCP protocol is used, TCP connection 'rtsp_c' is
   used. */
static int rtp_new_av_stream(RTSPContext *c,
                             int stream_index, struct sockaddr_in *dest_addr,
                             RTSPContext *rtsp_c)
{
    AVFormatContext *ctx;
    AVStream *st;
    char *ipaddr;
    URLContext *h = NULL;
    uint8_t *dummy_buf;
    int max_packet_size;

    /* now we can open the relevant output stream */
    ctx = avformat_alloc_context();
    if (!ctx)
        return -1;
    ctx->oformat = av_guess_format("rtp", NULL, NULL);

    st = av_mallocz(sizeof(AVStream));
    if (!st)
        goto fail;
    ctx->nb_streams = 1;
    ctx->streams = av_mallocz(sizeof(AVStream *) * ctx->nb_streams);
    if (!ctx->streams)
      goto fail;
    ctx->streams[0] = st;

    if (!c->stream->feed ||
        c->stream->feed == c->stream)
        memcpy(st, c->stream->streams[stream_index], sizeof(AVStream));
    else
        memcpy(st,
               c->stream->feed->streams[c->stream->feed_streams[stream_index]],
               sizeof(AVStream));
    st->priv_data = NULL;

    /* build destination RTP address */
    ipaddr = inet_ntoa(dest_addr->sin_addr);

    switch(c->rtp_protocol) {
    case RTSP_LOWER_TRANSPORT_UDP:
    case RTSP_LOWER_TRANSPORT_UDP_MULTICAST:
        /* RTP/UDP case */

        /* XXX: also pass as parameter to function ? */
        if (c->stream->is_multicast) {
            int ttl;
            ttl = c->stream->multicast_ttl;
            if (!ttl)
                ttl = 16;
            snprintf(ctx->filename, sizeof(ctx->filename),
                     "rtp://%s:%d?multicast=1&ttl=%d",
                     ipaddr, ntohs(dest_addr->sin_port), ttl);
        } else {
            snprintf(ctx->filename, sizeof(ctx->filename),
                     "rtp://%s:%d", ipaddr, ntohs(dest_addr->sin_port));
        }

        if (ffurl_open(&h, ctx->filename, AVIO_FLAG_WRITE, NULL, NULL) < 0)
            goto fail;
        c->rtp_handles[stream_index] = h;
        max_packet_size = h->max_packet_size;
        break;
    case RTSP_LOWER_TRANSPORT_TCP:
        /* RTP/TCP case */
        c->rtsp_c = rtsp_c;
        max_packet_size = RTSP_TCP_MAX_PACKET_SIZE;
        break;
    default:
        goto fail;
    }

    http_log("%s:%d - - \"PLAY %s/streamid=%d %s\"\n",
             ipaddr, ntohs(dest_addr->sin_port),
             c->stream->filename, stream_index, c->protocol);

    /* normally, no packets should be output here, but the packet size may
     * be checked */
    if (ffio_open_dyn_packet_buf(&ctx->pb, max_packet_size) < 0) {
        /* XXX: close stream */
        goto fail;
    }
    if (avformat_write_header(ctx, NULL) < 0) {
    fail:
        if (h)
            ffurl_close(h);
        av_free(ctx);
        return -1;
    }
    avio_close_dyn_buf(ctx->pb, &dummy_buf);
    av_free(dummy_buf);

    c->rtp_ctx[stream_index] = ctx;
    return 0;
}

static void rtsp_cmd_setup(RTSPContext *c, const char *url,
                           RTSPMessageHeader *h)
{
    FFStream *stream;
    int stream_index, rtp_port, rtcp_port;
    char buf[1024];
    char path1[1024];
    const char *path;
    RTSPContext *rtp_c;
    RTSPTransportField *th;
    struct sockaddr_in dest_addr;
    RTSPActionServerSetup setup;

    /* find which URL is asked */
    av_url_split(NULL, 0, NULL, 0, NULL, 0, NULL, path1, sizeof(path1), url);
    path = path1;
    if (*path == '/')
        path++;

    /* now check each stream */
    for(stream = first_stream; stream != NULL; stream = stream->next) {
        if (!stream->is_feed &&
            stream->fmt && !strcmp(stream->fmt->name, "rtp")) {
            /* accept aggregate filenames only if single stream */
            if (!strcmp(path, stream->filename)) {
                if (stream->nb_streams != 1) {
                    rtsp_reply_error(c, RTSP_STATUS_AGGREGATE);
                    return;
                }
                stream_index = 0;
                goto found;
            }

            for(stream_index = 0; stream_index < stream->nb_streams;
                stream_index++) {
                snprintf(buf, sizeof(buf), "%s/streamid=%d",
                         stream->filename, stream_index);
                if (!strcmp(path, buf))
                    goto found;
            }
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
        /* always prefer UDP */
        th = find_transport(h, RTSP_LOWER_TRANSPORT_UDP);
        if (!th) {
            th = find_transport(h, RTSP_LOWER_TRANSPORT_TCP);
            if (!th) {
                rtsp_reply_error(c, RTSP_STATUS_TRANSPORT);
                return;
            }
        }

        rtp_c = rtp_new_connection(&c->from_addr, stream, h->session_id,
                                   th->lower_transport);
        if (!rtp_c) {
            rtsp_reply_error(c, RTSP_STATUS_BANDWIDTH);
            return;
        }

        /* open input stream */
        if (open_input_stream(rtp_c, "") < 0) {
            rtsp_reply_error(c, RTSP_STATUS_INTERNAL);
            return;
        }
    }

    /* test if stream is OK (test needed because several SETUP needs
       to be done for a given file) */
    if (rtp_c->stream != stream) {
        rtsp_reply_error(c, RTSP_STATUS_SERVICE);
        return;
    }

    /* test if stream is already set up */
    if (rtp_c->rtp_ctx[stream_index]) {
        rtsp_reply_error(c, RTSP_STATUS_STATE);
        return;
    }

    /* check transport */
    th = find_transport(h, rtp_c->rtp_protocol);
    if (!th || (th->lower_transport == RTSP_LOWER_TRANSPORT_UDP &&
                th->client_port_min <= 0)) {
        rtsp_reply_error(c, RTSP_STATUS_TRANSPORT);
        return;
    }

    /* setup default options */
    setup.transport_option[0] = '\0';
    dest_addr = rtp_c->from_addr;
    dest_addr.sin_port = htons(th->client_port_min);

    /* setup stream */
    if (rtp_new_av_stream(rtp_c, stream_index, &dest_addr, c) < 0) {
        rtsp_reply_error(c, RTSP_STATUS_TRANSPORT);
        return;
    }

    /* now everything is OK, so we can send the connection parameters */
    rtsp_reply_header(c, RTSP_STATUS_OK);
    /* session ID */
    avio_printf(c->pb, "Session: %s\r\n", rtp_c->session_id);

    switch(rtp_c->rtp_protocol) {
    case RTSP_LOWER_TRANSPORT_UDP:
        rtp_port = ff_rtp_get_local_rtp_port(rtp_c->rtp_handles[stream_index]);
        rtcp_port = ff_rtp_get_local_rtcp_port(rtp_c->rtp_handles[stream_index]);
        avio_printf(c->pb, "Transport: RTP/AVP/UDP;unicast;"
                    "client_port=%d-%d;server_port=%d-%d",
                    th->client_port_min, th->client_port_max,
                    rtp_port, rtcp_port);
        break;
    case RTSP_LOWER_TRANSPORT_TCP:
        avio_printf(c->pb, "Transport: RTP/AVP/TCP;interleaved=%d-%d",
                    stream_index * 2, stream_index * 2 + 1);
        break;
    default:
        break;
    }
    if (setup.transport_option[0] != '\0')
        avio_printf(c->pb, ";%s", setup.transport_option);
    avio_printf(c->pb, "\r\n");


    avio_printf(c->pb, "\r\n");
}

/* find an RTP connection by using the session ID. Check consistency
   with filename */
static RTSPContext *find_rtp_session_with_url(const char *url,
                                              const char *session_id)
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
    path = path1;
    if (*path == '/')
        path++;
    if(!strcmp(path, rtp_c->stream->filename)) return rtp_c;
    for(s=0; s<rtp_c->stream->nb_streams; ++s) {
      snprintf(buf, sizeof(buf), "%s/streamid=%d",
        rtp_c->stream->filename, s);
      if(!strncmp(path, buf, sizeof(buf))) {
    // XXX: Should we reply with RTSP_STATUS_ONLY_AGGREGATE if nb_streams>1?
        return rtp_c;
      }
    }
    len = strlen(path);
    if (len > 0 && path[len - 1] == '/' &&
        !strncmp(path, rtp_c->stream->filename, len - 1))
        return rtp_c;
    return NULL;
}

static void rtsp_cmd_play(RTSPContext *c, const char *url, RTSPMessageHeader *h)
{
    RTSPContext *rtp_c;

    rtp_c = find_rtp_session_with_url(url, h->session_id);
    if (!rtp_c) {
        rtsp_reply_error(c, RTSP_STATUS_SESSION);
        return;
    }

    if (rtp_c->state != HTTPSTATE_SEND_DATA &&
        rtp_c->state != HTTPSTATE_WAIT_FEED &&
        rtp_c->state != HTTPSTATE_READY) {
        rtsp_reply_error(c, RTSP_STATUS_STATE);
        return;
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
        if (rtp_c->state != HTTPSTATE_SEND_DATA &&
            rtp_c->state != HTTPSTATE_WAIT_FEED) {
            rtsp_reply_error(c, RTSP_STATUS_STATE);
            return;
        }
        rtp_c->state = HTTPSTATE_READY;
        rtp_c->first_pts = AV_NOPTS_VALUE;
    }

    /* now everything is OK, so we can send the connection parameters */
    rtsp_reply_header(c, RTSP_STATUS_OK);
    /* session ID */
    avio_printf(c->pb, "Session: %s\r\n", rtp_c->session_id);
    avio_printf(c->pb, "\r\n");

    if (!pause_only)
        close_connection(rtp_c);
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

    printf("cmd = %s \n", cmd);
    printf("url = %s \n", url);
    printf("protocol = %s \n", protocol);
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

    if (!strcmp(cmd, "DESCRIBE")) {
        rtsp_cmd_describe(c, url);
        printf("DESCRIBE!!!\n");
    }
    else if (!strcmp(cmd, "OPTIONS")) {
        rtsp_cmd_options(c, url);
        printf("Options! \n");
    }
    else if (!strcmp(cmd, "SETUP")) {
        rtsp_cmd_setup(c, url, header);
        printf("Setup!!!\n");
    }
    else if (!strcmp(cmd, "PLAY")) {
        rtsp_cmd_play(c, url, header);
        printf("Play!!! \n");
    }
    else if (!strcmp(cmd, "PAUSE")) {
        rtsp_cmd_interrupt(c, url, header, 1);
        printf("PAUSE!!!\n");
    }
    else if (!strcmp(cmd, "TEARDOWN")) {
        rtsp_cmd_interrupt(c, url, header, 0);
        printf("TEARDOWN!!!\n");
    }
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

static int prepare_sdp_description(FFStream *stream, uint8_t **pbuffer,
                                   struct in_addr my_ip)
{
    AVFormatContext *avc;
    AVStream *avs = NULL;
    AVOutputFormat *rtp_format = av_guess_format("rtp", NULL, NULL);
    AVDictionaryEntry *entry = av_dict_get(stream->metadata, "title", NULL, 0);
    int i;

    avc =  avformat_alloc_context();
    if (avc == NULL || !rtp_format) {
        return -1;
    }
    avc->oformat = rtp_format;
    av_dict_set(&avc->metadata, "title",
                entry ? entry->value : "No Title", 0);
    avc->nb_streams = stream->nb_streams;
    if (stream->is_multicast) {
        snprintf(avc->filename, 1024, "rtp://%s:%d?multicast=1?ttl=%d",
                 inet_ntoa(stream->multicast_ip),
                 stream->multicast_port, stream->multicast_ttl);
    } else {
        snprintf(avc->filename, 1024, "rtp://0.0.0.0");
    }

    if (avc->nb_streams >= INT_MAX/sizeof(*avc->streams) ||
        !(avc->streams = av_malloc(avc->nb_streams * sizeof(*avc->streams))))
        goto sdp_done;
    if (avc->nb_streams >= INT_MAX/sizeof(*avs) ||
        !(avs = av_malloc(avc->nb_streams * sizeof(*avs))))
        goto sdp_done;

    for(i = 0; i < stream->nb_streams; i++) {
        avc->streams[i] = &avs[i];
        avc->streams[i]->codec = stream->streams[i]->codec;
    }
    *pbuffer = av_mallocz(2048);
    av_sdp_create(&avc, 1, *pbuffer, 2048);

 sdp_done:
    av_free(avc->streams);
    av_dict_free(&avc->metadata);
    av_free(avc);
    av_free(avs);

    return strlen(*pbuffer);
}

static int http_prepare_data(RTSPContext *c)
{
    int i, len, ret;
    AVFormatContext *ctx;

    av_freep(&c->pb_buffer);
    switch(c->state) {
    case HTTPSTATE_SEND_DATA_HEADER:
        ctx = avformat_alloc_context();
        c->fmt_ctx = *ctx;
        av_freep(&ctx);
        av_dict_copy(&(c->fmt_ctx.metadata), c->stream->metadata, 0);
        c->fmt_ctx.streams = av_mallocz(sizeof(AVStream *) * c->stream->nb_streams);

        for(i=0;i<c->stream->nb_streams;i++) {
            AVStream *src;
            c->fmt_ctx.streams[i] = av_mallocz(sizeof(AVStream));
            /* if file or feed, then just take streams from FFStream struct */
            if (!c->stream->feed ||
                c->stream->feed == c->stream)
                src = c->stream->streams[i];
            else
                src = c->stream->feed->streams[c->stream->feed_streams[i]];

            *(c->fmt_ctx.streams[i]) = *src;
            c->fmt_ctx.streams[i]->priv_data = 0;
            /* XXX: should be done in AVStream, not in codec */
            c->fmt_ctx.streams[i]->codec->frame_number = 0;
        }
        /* set output format parameters */
        c->fmt_ctx.oformat = c->stream->fmt;
        c->fmt_ctx.nb_streams = c->stream->nb_streams;

        c->got_key_frame = 0;

        /* prepare header and save header data in a stream */
        if (avio_open_dyn_buf(&c->fmt_ctx.pb) < 0) {
            /* XXX: potential leak */
            return -1;
        }
        c->fmt_ctx.pb->seekable = 0;

        /*
         * HACK to avoid MPEG-PS muxer to spit many underflow errors
         * Default value from FFmpeg
         * Try to set it using configuration option
         */
        c->fmt_ctx.max_delay = (int)(0.7*AV_TIME_BASE);

        if ((ret = avformat_write_header(&c->fmt_ctx, NULL)) < 0) {
            http_log("Error writing output header for stream '%s': %s\n",
                     c->stream->filename, av_err2str(ret));
            return ret;
        }
        av_dict_free(&c->fmt_ctx.metadata);

        len = avio_close_dyn_buf(c->fmt_ctx.pb, &c->pb_buffer);
        c->buffer_ptr = c->pb_buffer;
        c->buffer_end = c->pb_buffer + len;

        c->state = HTTPSTATE_SEND_DATA;
        c->last_packet_sent = 0;
        break;
    case HTTPSTATE_SEND_DATA:
        /* find a new packet */
        /* read a packet from the input stream */

        if (c->stream->max_time &&
            c->stream->max_time + c->start_time - cur_time < 0)
            /* We have timed out */
            c->state = HTTPSTATE_SEND_DATA_TRAILER;
        else {
            AVPacket pkt;
        redo:
            ret = av_read_frame(c->fmt_in, &pkt);
            if (ret < 0) {
                if (c->stream->feed) {
                    /* if coming from feed, it means we reached the end of the
                       ffm file, so must wait for more data */
                    c->state = HTTPSTATE_WAIT_FEED;
                    return 1; /* state changed */
                } else if (ret == AVERROR(EAGAIN)) {
                    /* input not ready, come back later */
                    return 0;
                } else {
                    if (c->stream->loop) {
                        avformat_close_input(&c->fmt_in);
                        if (open_input_stream(c, "") < 0)
                            goto no_loop;
                        goto redo;
                    } else {
                    no_loop:
                        /* must send trailer now because EOF or error */
                        c->state = HTTPSTATE_SEND_DATA_TRAILER;
                    }
                }
            } else {
                int source_index = pkt.stream_index;
                /* update first pts if needed */
                if (c->first_pts == AV_NOPTS_VALUE) {
                    c->first_pts = av_rescale_q(pkt.dts, c->fmt_in->streams[pkt.stream_index]->time_base, AV_TIME_BASE_Q);
                    c->start_time = cur_time;
                }
                /* send it to the appropriate stream */
                AVCodecContext *codec;
                AVStream *ist, *ost;
                send_it:
                    ist = c->fmt_in->streams[source_index];
                    /* specific handling for RTP: we use several
                     * output streams (one for each RTP connection).
                     * XXX: need more abstract handling */
                    if (c->is_packetized) {
                        /* compute send time and duration */
                        c->cur_pts = av_rescale_q(pkt.dts, ist->time_base, AV_TIME_BASE_Q);
                        c->cur_pts -= c->first_pts;
                        c->cur_frame_duration = av_rescale_q(pkt.duration, ist->time_base, AV_TIME_BASE_Q);
                        /* find RTP context */
                        c->packet_stream_index = pkt.stream_index;
                        ctx = c->rtp_ctx[c->packet_stream_index];
                        if(!ctx) {
                            av_free_packet(&pkt);
                            break;
                        }
                        codec = ctx->streams[0]->codec;
                        /* only one stream per RTP connection */
                        pkt.stream_index = 0;
                    } else {
                        ctx = &c->fmt_ctx;
                        /* Fudge here */
                        codec = ctx->streams[pkt.stream_index]->codec;
                    }

                    if (c->is_packetized) {
                        int max_packet_size;
                        if (c->rtp_protocol == RTSP_LOWER_TRANSPORT_TCP)
                            max_packet_size = RTSP_TCP_MAX_PACKET_SIZE;
                        else
                            max_packet_size = c->rtp_handles[c->packet_stream_index]->max_packet_size;
                        ret = ffio_open_dyn_packet_buf(&ctx->pb, max_packet_size);
                    } else {
                        ret = avio_open_dyn_buf(&ctx->pb);
                    }
                    if (ret < 0) {
                        /* XXX: potential leak */
                        return -1;
                    }
                    ost = ctx->streams[pkt.stream_index];

                    ctx->pb->seekable = 0;
                    if (pkt.dts != AV_NOPTS_VALUE)
                        pkt.dts = av_rescale_q(pkt.dts, ist->time_base, ost->time_base);
                    if (pkt.pts != AV_NOPTS_VALUE)
                        pkt.pts = av_rescale_q(pkt.pts, ist->time_base, ost->time_base);
                    pkt.duration = av_rescale_q(pkt.duration, ist->time_base, ost->time_base);
                    if ((ret = av_write_frame(ctx, &pkt)) < 0) {
                        http_log("Error writing frame to output for stream '%s': %s\n",
                                 c->stream->filename, av_err2str(ret));
                        c->state = HTTPSTATE_SEND_DATA_TRAILER;
                    }

                    len = avio_close_dyn_buf(ctx->pb, &c->pb_buffer);
                    c->cur_frame_bytes = len;
                    c->buffer_ptr = c->pb_buffer;
                    c->buffer_end = c->pb_buffer + len;

                    codec->frame_number++;
                    if (len == 0) {
                        av_free_packet(&pkt);
                        goto redo;
                    }
                av_free_packet(&pkt);
            }
        }
        break;
    default:
    case HTTPSTATE_SEND_DATA_TRAILER:
        /* last packet test ? */
        if (c->last_packet_sent || c->is_packetized)
            return -1;
        ctx = &c->fmt_ctx;
        /* prepare header */
        if (avio_open_dyn_buf(&ctx->pb) < 0) {
            /* XXX: potential leak */
            return -1;
        }
        c->fmt_ctx.pb->seekable = 0;
        av_write_trailer(ctx);
        len = avio_close_dyn_buf(ctx->pb, &c->pb_buffer);
        c->buffer_ptr = c->pb_buffer;
        c->buffer_end = c->pb_buffer + len;

        c->last_packet_sent = 1;
        break;
    }
    return 0;
}
/* should convert the format at the same time */
/* send data starting at c->buffer_ptr to the output connection
 * (either UDP or TCP) */
static int http_send_data(RTSPContext *c)
{
    int len, ret;

    for(;;) {
        if (c->buffer_ptr >= c->buffer_end) {
            ret = http_prepare_data(c);
            if (ret < 0)
                return -1;
            else if (ret != 0)
                /* state change requested */
                break;
        } else {
            if (c->is_packetized) {
                /* RTP data output */
                len = c->buffer_end - c->buffer_ptr;
                if (len < 4) {
                    /* fail safe - should never happen */
                fail1:
                    c->buffer_ptr = c->buffer_end;
                    return 0;
                }
                len = (c->buffer_ptr[0] << 24) |
                    (c->buffer_ptr[1] << 16) |
                    (c->buffer_ptr[2] << 8) |
                    (c->buffer_ptr[3]);
                if (len > (c->buffer_end - c->buffer_ptr))
                    goto fail1;
                if ((get_packet_send_clock(c) - get_server_clock(c)) > 0) {
                    /* nothing to send yet: we can wait */
                    return 0;
                }

                c->data_count += len;
                update_datarate(&c->datarate, c->data_count);
                if (c->stream)
                    c->stream->bytes_served += len;

                if (c->rtp_protocol == RTSP_LOWER_TRANSPORT_TCP) {
                    /* RTP packets are sent inside the RTSP TCP connection */
                    AVIOContext *pb;
                    int interleaved_index, size;
                    uint8_t header[4];
                    RTSPContext *rtsp_c;

                    rtsp_c = c->rtsp_c;
                    /* if no RTSP connection left, error */
                    if (!rtsp_c)
                        return -1;
                    /* if already sending something, then wait. */
                    if (rtsp_c->state != RTSPSTATE_WAIT_REQUEST)
                        break;
                    if (avio_open_dyn_buf(&pb) < 0)
                        goto fail1;
                    interleaved_index = c->packet_stream_index * 2;
                    /* RTCP packets are sent at odd indexes */
                    if (c->buffer_ptr[1] == 200)
                        interleaved_index++;
                    /* write RTSP TCP header */
                    header[0] = '$';
                    header[1] = interleaved_index;
                    header[2] = len >> 8;
                    header[3] = len;
                    avio_write(pb, header, 4);
                    /* write RTP packet data */
                    c->buffer_ptr += 4;
                    avio_write(pb, c->buffer_ptr, len);
                    size = avio_close_dyn_buf(pb, &c->packet_buffer);
                    /* prepare asynchronous TCP sending */
                    rtsp_c->packet_buffer_ptr = c->packet_buffer;
                    rtsp_c->packet_buffer_end = c->packet_buffer + size;
                    c->buffer_ptr += len;

                    /* send everything we can NOW */
                    len = send(rtsp_c->fd, rtsp_c->packet_buffer_ptr,
                                rtsp_c->packet_buffer_end - rtsp_c->packet_buffer_ptr, 0);
                    if (len > 0)
                        rtsp_c->packet_buffer_ptr += len;
                    if (rtsp_c->packet_buffer_ptr < rtsp_c->packet_buffer_end) {
                        /* if we could not send all the data, we will
                           send it later, so a new state is needed to
                           "lock" the RTSP TCP connection */
                        rtsp_c->state = RTSPSTATE_SEND_PACKET;
                        break;
                    } else
                        /* all data has been sent */
                        av_freep(&c->packet_buffer);
                } else {
                    /* send RTP packet directly in UDP */
                    c->buffer_ptr += 4;
                    ffurl_write(c->rtp_handles[c->packet_stream_index],
                                c->buffer_ptr, len);
                    c->buffer_ptr += len;
                    /* here we continue as we can send several packets per 10 ms slot */
                }
            } else {
                /* TCP data output */
                len = send(c->fd, c->buffer_ptr, c->buffer_end - c->buffer_ptr, 0);
                if (len < 0) {
                  return 0;
                  /*
                    if (ff_neterrno() != AVERROR(EAGAIN) &&
                        ff_neterrno() != AVERROR(EINTR))
                         error : close connection 
                        return -1;
                    else
                        return 0;
                        */
                } else
                    c->buffer_ptr += len;

                c->data_count += len;
                update_datarate(&c->datarate, c->data_count);
                if (c->stream)
                    c->stream->bytes_served += len;
                break;
            }
        }
    } /* for(;;) */
    return 0;
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

static AVStream *add_av_stream1(FFStream *stream, AVCodecContext *codec, int copy)
{
    AVStream *fst;

    if(stream->nb_streams >= FF_ARRAY_ELEMS(stream->streams))
        return NULL;

    fst = av_mallocz(sizeof(AVStream));
    if (!fst)
        return NULL;
    if (copy) {
        fst->codec = avcodec_alloc_context3(NULL);
        memcpy(fst->codec, codec, sizeof(AVCodecContext));
        if (codec->extradata_size) {
            fst->codec->extradata = av_mallocz(codec->extradata_size + FF_INPUT_BUFFER_PADDING_SIZE);
            memcpy(fst->codec->extradata, codec->extradata,
                codec->extradata_size);
        }
    } else {
        /* live streams must use the actual feed's codec since it may be
         * updated later to carry extradata needed by them.
         */
        fst->codec = codec;
    }
    fst->priv_data = av_mallocz(sizeof(FeedData));
    fst->index = stream->nb_streams;
    avpriv_set_pts_info(fst, 33, 1, 90000);
    fst->sample_aspect_ratio = codec->sample_aspect_ratio;
    stream->streams[stream->nb_streams++] = fst;
    return fst;
}

/* return the stream number in the feed */
static int add_av_stream(FFStream *feed, AVStream *st)
{
    AVStream *fst;
    AVCodecContext *av, *av1;
    int i;

    av = st->codec;
    for(i=0;i<feed->nb_streams;i++) {
        st = feed->streams[i];
        av1 = st->codec;
        if (av1->codec_id == av->codec_id &&
            av1->codec_type == av->codec_type &&
            av1->bit_rate == av->bit_rate) {

            switch(av->codec_type) {
            case AVMEDIA_TYPE_AUDIO:
                if (av1->channels == av->channels &&
                    av1->sample_rate == av->sample_rate)
                    return i;
                break;
            case AVMEDIA_TYPE_VIDEO:
                if (av1->width == av->width &&
                    av1->height == av->height &&
                    av1->time_base.den == av->time_base.den &&
                    av1->time_base.num == av->time_base.num &&
                    av1->gop_size == av->gop_size)
                    return i;
                break;
            default:
                abort();
            }
        }
    }

    fst = add_av_stream1(feed, av, 0);
    if (!fst)
        return -1;
    return feed->nb_streams - 1;
}

static void remove_stream(FFStream *stream)
{
    FFStream **ps;
    ps = &first_stream;
    while (*ps != NULL) {
        if (*ps == stream)
            *ps = (*ps)->next;
        else
            ps = &(*ps)->next;
    }
}

/* specific MPEG4 handling : we extract the raw parameters */
static void extract_mpeg4_header(AVFormatContext *infile)
{
    int mpeg4_count, i, size;
    AVPacket pkt;
    AVStream *st;
    const uint8_t *p;

    infile->flags |= AVFMT_FLAG_NOFILLIN | AVFMT_FLAG_NOPARSE;

    mpeg4_count = 0;
    for(i=0;i<infile->nb_streams;i++) {
        st = infile->streams[i];
        if (st->codec->codec_id == AV_CODEC_ID_MPEG4 &&
            st->codec->extradata_size == 0) {
            mpeg4_count++;
        }
    }
    if (!mpeg4_count)
        return;

    printf("MPEG4 without extra data: trying to find header in %s\n", infile->filename);
    while (mpeg4_count > 0) {
        if (av_read_frame(infile, &pkt) < 0)
            break;
        st = infile->streams[pkt.stream_index];
        if (st->codec->codec_id == AV_CODEC_ID_MPEG4 &&
            st->codec->extradata_size == 0) {
            av_freep(&st->codec->extradata);
            /* fill extradata with the header */
            /* XXX: we make hard suppositions here ! */
            p = pkt.data;
            while (p < pkt.data + pkt.size - 4) {
                /* stop when vop header is found */
                if (p[0] == 0x00 && p[1] == 0x00 &&
                    p[2] == 0x01 && p[3] == 0xb6) {
                    size = p - pkt.data;
                    //                    av_hex_dump_log(infile, AV_LOG_DEBUG, pkt.data, size);
                    st->codec->extradata = av_mallocz(size + FF_INPUT_BUFFER_PADDING_SIZE);
                    st->codec->extradata_size = size;
                    memcpy(st->codec->extradata, pkt.data, size);
                    break;
                }
                p++;
            }
            mpeg4_count--;
        }
        av_free_packet(&pkt);
    }
}
/* compute the needed AVStream for each file */
static void build_file_streams(void)
{
    FFStream *stream, *stream_next;
    int i, ret;

    /* gather all streams */
    for(stream = first_stream; stream != NULL; stream = stream_next) {
        AVFormatContext *infile = NULL;
        stream_next = stream->next;
        if (stream->stream_type == STREAM_TYPE_LIVE &&
            !stream->feed) {
            /* the stream comes from a file */
            /* try to open the file */
            /* open stream */
            if (stream->fmt && !strcmp(stream->fmt->name, "rtp")) {
                /* specific case : if transport stream output to RTP,
                   we use a raw transport stream reader */
                printf("rtp!!! \n");
                av_dict_set(&stream->in_opts, "mpeg2ts_compute_pcr", "1", 0);
            }

            printf("filename = %s!!! \n", stream->feed_filename);
            if (!stream->feed_filename[0]) {
                http_log("Unspecified feed file for stream '%s'\n", stream->filename);
                goto fail;
            }

            http_log("Opening feed file '%s' for stream '%s'\n", stream->feed_filename, stream->filename);
            if ((ret = avformat_open_input(&infile, stream->feed_filename, stream->ifmt, &stream->in_opts)) < 0) {
                http_log("Could not open '%s': %s\n", stream->feed_filename, av_err2str(ret));
                /* remove stream (no need to spend more time on it) */
            fail:
                remove_stream(stream);
            } else {
                /* find all the AVStreams inside and reference them in
                   'stream' */
                if (avformat_find_stream_info(infile, NULL) < 0) {
                    http_log("Could not find codec parameters from '%s'\n",
                             stream->feed_filename);
                    avformat_close_input(&infile);
                    goto fail;
                }
                extract_mpeg4_header(infile);

                for(i=0;i<infile->nb_streams;i++)
                    add_av_stream1(stream, infile->streams[i]->codec, 1);

                avformat_close_input(&infile);
            }
        }
    }
}


int main(int argc, char **argv)
{
    struct sigaction sigact = { { 0 } };
    int ret = 0;

    // set rtsp addr.
    //my_rtsp_addr.sin_port = htons(5454); 
    //resolve_host(&my_rtsp_addr.sin_addr, "0.0.0.0");

    config_filename = av_strdup("/etc/ffserver.conf");

//    parse_loglevel(argc, argv, options);
    av_register_all();
    //avformat_network_init();

//    show_banner(argc, argv, options);

 //   my_program_name = argv[0];

//    parse_options(NULL, argc, argv, options, NULL);

    unsetenv("http_proxy");             /* Kill the http_proxy */

    av_lfg_init(&random_state, av_get_random_seed());

    /*
    sigact.sa_handler = handle_child_exit;
    sigact.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    sigaction(SIGCHLD, &sigact, 0);

    */

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
