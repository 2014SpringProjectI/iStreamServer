typedef struct iIndex {
  unsigned int pos;
  unsigned char pcr[6];
  unsigned int frame_num;
  struct iIndex *next;
} iIndex;

typedef struct {
  unsigned int total_length; // total # of ts packets
  unsigned int bit_rate; // kbps 
  unsigned char encoding_format; // 0 == h264, 1 == h265
  unsigned int duration; // seconds 
} iIndexHeader;

void dump_iIndexHeader(iIndexHeader *hdr); 
void dump_iIndex(iIndex *index);
double get_iIndex_PCR(iIndex *index);
iIndex* start_parse_index_file(const char *idx_filename, iIndexHeader *hdr); // return the first node of iIndex
