#include "iIndexParser.h"

enum HTTPState {
    HTTPSTATE_READY,
    HTTPSTATE_WAIT_REQUEST,
    RTPSTATE_SEND_DATA,          /* sending TCP or UDP data */
    HTTPSTATE_RECEIVE_DATA,
    RTSPSTATE_WAIT_REQUEST,
    RTSPSTATE_SEND_REPLY,
    RTSPSTATE_SEND_PACKET,
};

static const char *http_state[] = {
    "HTTP_WAIT_REQUEST",
    "HTTP_SEND_HEADER",
    "SEND_DATA",
    "RECEIVE_DATA",
    "RTSP_WAIT_REQUEST",
    "RTSP_SEND_REPLY",
    "RTSP_SEND_PACKET",
};

typedef struct iStream {
  char name[1024]; // for identify stream name 
  char filename[1024];
  char idx_filename[1024];
  struct iStream *next;
  unsigned int bit_rate;
  unsigned int duration;
  unsigned int total_length;
  iIndexHeader *idx_hdr;
  iIndex *first_idx;
  const char *codec_name;
} iStream;

typedef struct RTSPContext {
  enum HTTPState state;
  int64_t timeout;
  int fd; /* socket file descriptor */
  uint8_t *buffer_ptr, *buffer_end;
  struct sockaddr_in from_addr; /* origin */
  struct sockaddr_in to_addr; // target addr for rtp/udp request
  struct pollfd *poll_entry; /* used when polling */
  struct RTSPContext *next;
  iStream *stream;
  int64_t start_time;            /* In milliseconds - this wraps fairly often */
  bool last_packet_sent; /* true if last data packet was sent */
  int buffer_size;
  uint8_t *buffer;
  int seq; /* RTSP sequence number */
  char session_id[32]; /* session id */
  int udp_fd;
  int udp_port;
  int64_t cur_offset;
  int64_t served_bytes;
  iIndex *cur_idx;
  uint8_t *pb_buffer; /* XXX: use that in all the code */
  AVIOContext *pb;
  int cur_seq;
  char protocol[16];
  char method[16];
  char url[128];
  double ntp_start_time;
  FILE *ts;
} RTSPContext;

typedef struct RTSPActionServerSetup {
    uint32_t ipaddr;
    char transport_option[512];
} RTSPActionServerSetup;

#define RTP_LITTLE_ENDIAN 1
#define RTP_SEQ_MOD (1<<16)

typedef struct {
#if RTP_BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif RTP_LITTLE_ENDIAN
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
    unsigned int seq:16;      /* sequence number */
    unsigned int ts;               /* timestamp */
    unsigned int ssrc;             /* synchronization source */
   /* u_int32 csrc[1];           optional CSRC list */
} rtp_hdr_t;

static int rtsp_parse_request(RTSPContext *c);
static void close_connection(RTSPContext *c);
static void new_connection(int server_fd);
static void start_wait_request(RTSPContext *c);
static void rtsp_cmd_options(RTSPContext *c, const char *url);
static void rtsp_cmd_describe(RTSPContext *c, const char *url);
static void rtsp_cmd_setup(RTSPContext *c, const char *url, RTSPMessageHeader *h);
static void rtsp_cmd_play(RTSPContext *c, const char *url, RTSPMessageHeader *h);
static void rtsp_cmd_interrupt(RTSPContext *c, const char *url, RTSPMessageHeader *h, int pause_only);
static RTSPContext *find_rtp_session(const char *session_id);
static RTSPContext *find_rtp_session_with_url(const char *url, const char *session_id);
static RTSPContext *rtp_new_connection(struct sockaddr_in *from_addr,iStream *stream, const char *session_id);
static int rtp_new_stream(RTSPContext *c, struct sockaddr_in *dest_addr);
int resolve_host(struct in_addr *sin_addr, const char *hostname);
static int rtp_send_data(RTSPContext *c);
int generate_sdp_context(iStream *stream, unsigned char **buf);
