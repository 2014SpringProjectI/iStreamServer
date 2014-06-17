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
void dump_through_iIndex(iIndex *index);
double get_iIndex_PCR(iIndex *index);
// return pakcet position! not bytes position! multipliy 188 to thie value to optaion bytes offset.
int64_t get_closest_iframe_pos(iIndex *first_idx, int64_t cur_pos);
int64_t get_closest_iframe_pos_by_time(iIndex *first_idx, double cur_time);
iIndex* start_parse_index_file(const char *idx_filename, iIndexHeader *hdr); // return the first node of iIndex
