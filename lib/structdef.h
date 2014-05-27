#define MAX_STREAMS 20

#define IOBUFFER_INIT_SIZE 8192
/* timeouts are in ms */
#define HTTP_REQUEST_TIMEOUT (15 * 1000)
#define RTSP_REQUEST_TIMEOUT (3600 * 24 * 1000)
#define SYNC_TIMEOUT (10 * 1000)
#define INT_MAX 2147483647

#define AVIO_FLAG_READ  1                                      /**< read-only */
#define AVIO_FLAG_WRITE 2                                      /**< write-only */
#define AVIO_FLAG_READ_WRITE (AVIO_FLAG_READ|AVIO_FLAG_WRITE)  /**< read-write pseudo flag */
#define AVIO_SEEKABLE_NORMAL 0x0001

#define FF_INPUT_BUFFER_PADDING_SIZE 16 // in libavcodec/acvodec.h

#define SPACE_CHARS " \t\r\n"

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

typedef struct RTSPActionServerSetup {
    uint32_t ipaddr;
    char transport_option[512];
} RTSPActionServerSetup;

typedef struct {
    int64_t count1, count2;
    int64_t time1, time2;
} DataRateData;

typedef struct AVIOContext {
    unsigned char *buffer;  /**< Start of the buffer. */
    int buffer_size;        /**< Maximum buffer size */
    unsigned char *buf_ptr; /**< Current position in the buffer */
    unsigned char *buf_end; /**< End of the data, may be less than
                                 buffer+buffer_size if the read function returned
                                 less data than requested, e.g. for streams where
                                 no more data has been received yet. */
    void *opaque;           /**< A private pointer, passed to the read/write/seek/...
                                 functions. */
    int (*read_packet)(void *opaque, uint8_t *buf, int buf_size);
    int (*write_packet)(void *opaque, uint8_t *buf, int buf_size);
    int64_t (*seek)(void *opaque, int64_t offset, int whence);
    int64_t pos;            /**< position in the file of the current buffer */
    int must_flush;         /**< true if the next seek should flush */
    int eof_reached;        /**< true if eof reached */
    int write_flag;         /**< true if open for writing */
    int max_packet_size;
    unsigned long checksum;
    unsigned char *checksum_ptr;
    unsigned long (*update_checksum)(unsigned long checksum, const uint8_t *buf, unsigned int size);
    int error;              /**< contains the error code or 0 if no error happened */
    /**
     * Pause or resume playback for network streaming protocols - e.g. MMS.
     */
    int (*read_pause)(void *opaque, int pause);
    /**
     * Seek to a given timestamp in stream with the specified stream_index.
     * Needed for some network streaming protocols which don't support seeking
     * to byte position.
     */
    int64_t (*read_seek)(void *opaque, int stream_index,
                         int64_t timestamp, int flags);
    int seekable;
    int64_t maxsize;
    int direct;
    int64_t bytes_read;
    int seek_count;
    int writeout_count;
    int orig_buffer_size;
} AVIOContext;

/* context associated with one connection */
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
    /* feed input */
    int feed_fd;
    /* input format handling */
    //AVFormatContext *fmt_in;
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
    //struct FFStream *stream;
    /* -1 is invalid stream */
    int feed_streams[MAX_STREAMS]; /* index of streams in the feed */
    int switch_feed_streams[MAX_STREAMS]; /* index of streams in the feed */
    int switch_pending;
    //AVFormatContext fmt_ctx; /* instance of FFStream for one user */
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
    //enum RTSPLowerTransport rtp_protocol;
    char session_id[32]; /* session id */
    //AVFormatContext *rtp_ctx[MAX_STREAMS];

    /* RTP/UDP specific */
    //URLContext *rtp_handles[MAX_STREAMS];

    /* RTP/TCP specific */
    struct RTSPContext *rtsp_c;
    uint8_t *packet_buffer, *packet_buffer_ptr, *packet_buffer_end;
} RTSPContext;

typedef struct FeedData {
    long long data_count;
    float avg_frame_size;   /* frame size averaged over last frames with exponential mean */
} FeedData;

/* RTSP handling */
enum RTSPLowerTransport {
    RTSP_LOWER_TRANSPORT_UDP = 0,           /**< UDP/unicast */
    RTSP_LOWER_TRANSPORT_TCP = 1,           /**< TCP; interleaved in RTSP */
    RTSP_LOWER_TRANSPORT_UDP_MULTICAST = 2, /**< UDP/multicast */
    RTSP_LOWER_TRANSPORT_NB,
    RTSP_LOWER_TRANSPORT_HTTP = 8,          /**< HTTP tunneled - not a proper
                                                 transport mode as such,
                                                 only for use via AVOptions */
    RTSP_LOWER_TRANSPORT_CUSTOM = 16,       /**< Custom IO - not a public
                                                 option for lower_transport_mask,
                                                 but set in the SDP demuxer based
                                                 on a flag. */
};
enum RTSPTransport {
    RTSP_TRANSPORT_RTP, /**< Standards-compliant RTP */
    RTSP_TRANSPORT_RDT, /**< Realmedia Data Transport */
    RTSP_TRANSPORT_RAW, /**< Raw data (over UDP) */
    RTSP_TRANSPORT_NB
};
typedef struct RTSPTransportField {
    /** interleave ids, if TCP transport; each TCP/RTSP data packet starts
     * with a '$', stream length and stream ID. If the stream ID is within
     * the range of this interleaved_min-max, then the packet belongs to
     * this stream. */
    int interleaved_min, interleaved_max;

    /** UDP multicast port range; the ports to which we should connect to
     * receive multicast UDP data. */
    int port_min, port_max;

    /** UDP client ports; these should be the local ports of the UDP RTP
     * (and RTCP) sockets over which we receive RTP/RTCP data. */
    int client_port_min, client_port_max;

    /** UDP unicast server port range; the ports to which we should connect
     * to receive unicast UDP RTP/RTCP data. */
    int server_port_min, server_port_max;

    /** time-to-live value (required for multicast); the amount of HOPs that
     * packets will be allowed to make before being discarded. */
    int ttl;

    /** transport set to record data */
    int mode_record;

    struct sockaddr_storage destination; /**< destination IP address */
    char source[INET6_ADDRSTRLEN + 1]; /**< source IP address */

    /** data/packet transport protocol; e.g. RTP or RDT */
    enum RTSPTransport transport;

    /** network layer transport protocol; e.g. TCP or UDP uni-/multicast */
    enum RTSPLowerTransport lower_transport;
} RTSPTransportField;

enum RTSPStatusCode {
RTSP_STATUS_CONTINUE             =100,
RTSP_STATUS_OK                   =200,
RTSP_STATUS_CREATED              =201,
RTSP_STATUS_LOW_ON_STORAGE_SPACE =250,
RTSP_STATUS_MULTIPLE_CHOICES     =300,
RTSP_STATUS_MOVED_PERMANENTLY    =301,
RTSP_STATUS_MOVED_TEMPORARILY    =302,
RTSP_STATUS_SEE_OTHER            =303,
RTSP_STATUS_NOT_MODIFIED         =304,
RTSP_STATUS_USE_PROXY            =305,
RTSP_STATUS_BAD_REQUEST          =400,
RTSP_STATUS_UNAUTHORIZED         =401,
RTSP_STATUS_PAYMENT_REQUIRED     =402,
RTSP_STATUS_FORBIDDEN            =403,
RTSP_STATUS_NOT_FOUND            =404,
RTSP_STATUS_METHOD               =405,
RTSP_STATUS_NOT_ACCEPTABLE       =406,
RTSP_STATUS_PROXY_AUTH_REQUIRED  =407,
RTSP_STATUS_REQ_TIME_OUT         =408,
RTSP_STATUS_GONE                 =410,
RTSP_STATUS_LENGTH_REQUIRED      =411,
RTSP_STATUS_PRECONDITION_FAILED  =412,
RTSP_STATUS_REQ_ENTITY_2LARGE    =413,
RTSP_STATUS_REQ_URI_2LARGE       =414,
RTSP_STATUS_UNSUPPORTED_MTYPE    =415,
RTSP_STATUS_PARAM_NOT_UNDERSTOOD =451,
RTSP_STATUS_CONFERENCE_NOT_FOUND =452,
RTSP_STATUS_BANDWIDTH            =453,
RTSP_STATUS_SESSION              =454,
RTSP_STATUS_STATE                =455,
RTSP_STATUS_INVALID_HEADER_FIELD =456,
RTSP_STATUS_INVALID_RANGE        =457,
RTSP_STATUS_RONLY_PARAMETER      =458,
RTSP_STATUS_AGGREGATE            =459,
RTSP_STATUS_ONLY_AGGREGATE       =460,
RTSP_STATUS_TRANSPORT            =461,
RTSP_STATUS_UNREACHABLE          =462,
RTSP_STATUS_INTERNAL             =500,
RTSP_STATUS_NOT_IMPLEMENTED      =501,
RTSP_STATUS_BAD_GATEWAY          =502,
RTSP_STATUS_SERVICE              =503,
RTSP_STATUS_GATEWAY_TIME_OUT     =504,
RTSP_STATUS_VERSION              =505,
RTSP_STATUS_UNSUPPORTED_OPTION   =551,
};

#define RTSP_MAX_TRANSPORTS 8
typedef struct RTSPMessageHeader {
    /** length of the data following this header */
    int content_length;

    enum RTSPStatusCode status_code; /**< response code from server */

    /** number of items in the 'transports' variable below */
    int nb_transports;

    /** Time range of the streams that the server will stream. In
     * AV_TIME_BASE unit, AV_NOPTS_VALUE if not used */
    int64_t range_start, range_end;

    /** describes the complete "Transport:" line of the server in response
     * to a SETUP RTSP command by the client */
    RTSPTransportField transports[RTSP_MAX_TRANSPORTS];

    int seq;                         /**< sequence number */

    /** the "Session:" field. This value is initially set by the server and
     * should be re-transmitted by the client in every RTSP command. */
    char session_id[512];

    /** the "Location:" field. This value is used to handle redirection.
     */
    char location[4096];

    /** the "RealChallenge1:" field from the server */
    char real_challenge[64];

    /** the "Server: field, which can be used to identify some special-case
     * servers that are not 100% standards-compliant. We use this to identify
     * Windows Media Server, which has a value "WMServer/v.e.r.sion", where
     * version is a sequence of digits (e.g. 9.0.0.3372). Helix/Real servers
     * use something like "Helix [..] Server Version v.e.r.sion (platform)
     * (RealServer compatible)" or "RealServer Version v.e.r.sion (platform)",
     * where platform is the output of $uname -msr | sed 's/ /-/g'. */
    char server[64];

    /** The "timeout" comes as part of the server response to the "SETUP"
     * command, in the "Session: <xyz>[;timeout=<value>]" line. It is the
     * time, in seconds, that the server will go without traffic over the
     * RTSP/TCP connection before it closes the connection. To prevent
     * this, sent dummy requests (e.g. OPTIONS) with intervals smaller
     * than this value. */
    int timeout;

    /** The "Notice" or "X-Notice" field value. See
     * http://tools.ietf.org/html/draft-stiemerling-rtsp-announce-00
     * for a complete list of supported values. */
    int notice;

    /** The "reason" is meant to specify better the meaning of the error code
     * returned
     */
    char reason[256];

    /**
     * Content type header
     */
    char content_type[64];
} RTSPMessageHeader;

/* output in a dynamic buffer */
typedef struct DynBuffer {
    int pos, size, allocated_size;
    uint8_t *buffer;
    int io_buffer_size;
    uint8_t io_buffer[1];
} DynBuffer;

typedef struct RTSPState {
    //const AVClass *class;             /**< Class for private options. */
    //URLContext *rtsp_hd; /* RTSP TCP connection handle */

    /** number of items in the 'rtsp_streams' variable */
    int nb_rtsp_streams;

    struct RTSPStream **rtsp_streams; /**< streams in this session */

    /** indicator of whether we are currently receiving data from the
     * server. Basically this isn't more than a simple cache of the
     * last PLAY/PAUSE command sent to the server, to make sure we don't
     * send 2x the same unexpectedly or commands in the wrong state. */
    //enum RTSPClientState state;

    /** the seek value requested when calling av_seek_frame(). This value
     * is subsequently used as part of the "Range" parameter when emitting
     * the RTSP PLAY command. If we are currently playing, this command is
     * called instantly. If we are currently paused, this command is called
     * whenever we resume playback. Either way, the value is only used once,
     * see rtsp_read_play() and rtsp_read_seek(). */
    int64_t seek_timestamp;

    int seq;                          /**< RTSP command sequence number */

    /** copy of RTSPMessageHeader->session_id, i.e. the server-provided session
     * identifier that the client should re-transmit in each RTSP command */
    char session_id[512];

    /** copy of RTSPMessageHeader->timeout, i.e. the time (in seconds) that
     * the server will go without traffic on the RTSP/TCP line before it
     * closes the connection. */
    int timeout;

    /** timestamp of the last RTSP command that we sent to the RTSP server.
     * This is used to calculate when to send dummy commands to keep the
     * connection alive, in conjunction with timeout. */
    int64_t last_cmd_time;

    /** the negotiated data/packet transport protocol; e.g. RTP or RDT */
    enum RTSPTransport transport;

    /** the negotiated network layer transport protocol; e.g. TCP or UDP
     * uni-/multicast */
    enum RTSPLowerTransport lower_transport;

    /** brand of server that we're talking to; e.g. WMS, REAL or other.
     * Detected based on the value of RTSPMessageHeader->server or the presence
     * of RTSPMessageHeader->real_challenge */
    //enum RTSPServerType server_type;

    /** the "RealChallenge1:" field from the server */
    char real_challenge[64];

    /** plaintext authorization line (username:password) */
    char auth[128];

    /** authentication state */
    //HTTPAuthState auth_state;

    /** The last reply of the server to a RTSP command */
    char last_reply[2048]; /* XXX: allocate ? */

    /** RTSPStream->transport_priv of the last stream that we read a
     * packet from */
    void *cur_transport_priv;

    /** The following are used for Real stream selection */
    //@{
    /** whether we need to send a "SET_PARAMETER Subscribe:" command */
    int need_subscription;

    /** stream setup during the last frame read. This is used to detect if
     * we need to subscribe or unsubscribe to any new streams. */
    enum AVDiscard *real_setup_cache;

    /** current stream setup. This is a temporary buffer used to compare
     * current setup to previous frame setup. */
    enum AVDiscard *real_setup;

    /** the last value of the "SET_PARAMETER Subscribe:" RTSP command.
     * this is used to send the same "Unsubscribe:" if stream setup changed,
     * before sending a new "Subscribe:" command. */
    char last_subscription[1024];
    //@}

    /** The following are used for RTP/ASF streams */
    //@{
    /** ASF demuxer context for the embedded ASF stream from WMS servers */
    //AVFormatContext *asf_ctx;

    /** cache for position of the asf demuxer, since we load a new
     * data packet in the bytecontext for each incoming RTSP packet. */
    uint64_t asf_pb_pos;
    //@}

    /** some MS RTSP streams contain a URL in the SDP that we need to use
     * for all subsequent RTSP requests, rather than the input URI; in
     * other cases, this is a copy of AVFormatContext->filename. */
    char control_uri[1024];

    /** The following are used for parsing raw mpegts in udp */
    //@{
    struct MpegTSContext *ts;
    int recvbuf_pos;
    int recvbuf_len;
    //@}

    /** Additional output handle, used when input and output are done
     * separately, eg for HTTP tunneling. */
    //URLContext *rtsp_hd_out;

    /** RTSP transport mode, such as plain or tunneled. */
    //enum RTSPControlTransport control_transport;

    /* Number of RTCP BYE packets the RTSP session has received.
     * An EOF is propagated back if nb_byes == nb_streams.
     * This is reset after a seek. */
    int nb_byes;

    /** Reusable buffer for receiving packets */
    uint8_t* recvbuf;

    /**
     * A mask with all requested transport methods
     */
    int lower_transport_mask;

    /**
     * The number of returned packets
     */
    uint64_t packets;

    /**
     * Polling array for udp
     */
    struct pollfd *p;

    /**
     * Whether the server supports the GET_PARAMETER method.
     */
    int get_parameter_supported;

    /**
     * Do not begin to play the stream immediately.
     */
    int initial_pause;

    /**
     * Option flags for the chained RTP muxer.
     */
    int rtp_muxer_flags;

    /** Whether the server accepts the x-Dynamic-Rate header */
    int accept_dynamic_rate;

    /**
     * Various option flags for the RTSP muxer/demuxer.
     */
    int rtsp_flags;

    /**
     * Mask of all requested media types
     */
    int media_type_mask;

    /**
     * Minimum and maximum local UDP ports.
     */
    int rtp_port_min, rtp_port_max;

    /**
     * Timeout to wait for incoming connections.
     */
    int initial_timeout;

    /**
     * timeout of socket i/o operations.
     */
    int stimeout;

    /**
     * Size of RTP packet reordering queue.
     */
    int reordering_queue_size;

    /**
     * User-Agent string
     */
    char *user_agent;
} RTSPState;
