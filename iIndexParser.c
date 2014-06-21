#include <stdio.h>
#include <stdlib.h>
#include "iIndexParser.h"
#include <string.h>

void dump_iIndexHeader(iIndexHeader *hdr)
{
  printf("------------ iIndexHeader dump----------\n");
  printf("------total_length = %u\n", hdr->total_length);
  printf("------bit_rate = %u kbps\n", hdr->bit_rate);
  const char *encoding;
  if (hdr->encoding_format == 0)
    encoding = "H.264";
  else
    encoding = "H.265";
  printf("------encoding_format = %s\n", encoding);
  printf("------duration = %u seconds\n", hdr->duration);
  return;
}

void dump_iIndex(iIndex *index)
{
  printf("------------ iIndex dump----------\n");
  printf("------pos = %u\n", index->pos);
  printf("------pcr = %.3fs\n", get_iIndex_PCR(index));
  printf("------frame_num = %d\n", index->frame_num);
  return;
}

void dump_through_iIndex(iIndex *index)
{
  int cnt = 0;
  printf("dump through index!! ---- \n");
  iIndex *i;
  iIndex *idx_next;
  for (i = index; i != NULL; i = idx_next)
  {
    idx_next = i->next;
    dump_iIndex(i);
    cnt++;
  }
  printf("index search finisehd! cnt = %d\n", cnt);
}

double get_iIndex_PCR(iIndex *index)
{
	uint8_t *data = index->pcr; // Offset in TS packet
	uint64_t pcr_base;
	uint16_t pcr_ext;
	pcr_base  = (uint64_t)data[0] << 25;
	pcr_base += (uint64_t)data[1] << 17;
	pcr_base += (uint64_t)data[2] << 9;
	pcr_base += (uint64_t)data[3] << 1;
	pcr_base += (uint64_t)data[4] >> 7;
	pcr_ext   = ((uint16_t)data[4] & 0x01) << 8;
	pcr_ext  += (uint16_t)data[5];
	return ((pcr_base / 90000.0f) + (pcr_ext/27000000.0f));
}

int64_t get_closest_iframe_pos_by_time(iIndex *first_idx, double cur_time)
{
  iIndex *i;
  if (cur_time <= get_iIndex_PCR(first_idx))
    return 0;

  for (i = first_idx; i != NULL; i = i->next)
  {
    // next iframe pos가 cur pos보다 크면, cur iframe이 가장 가까운 iframe! 
    if (i->next != NULL && get_iIndex_PCR(i->next) >= cur_time)
      return i->pos;
  }
  // can't find. 
  return 0;
}
iIndex* get_closest_iframe_by_pos(iIndex *first_idx, int64_t cur_pos)
{
  iIndex *i;
  if (cur_pos <= first_idx->pos)
    return first_idx;

  for (i = first_idx; i != NULL; i = i->next)
  {
    // next iframe pos가 cur pos보다 크면, cur iframe이 가장 가까운 iframe! 
    if (i->next != NULL &&i->next->pos >= cur_pos)
      return i;
  }
  // can't find. 
  return NULL;
}
iIndex* get_closest_iframe_by_time(iIndex *first_idx, int64_t cur_time)
{
  iIndex *i;
  if (cur_time <= get_iIndex_PCR(first_idx))
    return first_idx;

  for (i = first_idx; i != NULL; i = i->next)
  {
    // next iframe pos가 cur pos보다 크면, cur iframe이 가장 가까운 iframe! 
    if (i->next != NULL && get_iIndex_PCR(i->next) >= cur_time)
      return i;
  }
  // can't find. 
  return NULL;
}

int64_t get_closest_iframe_pos(iIndex *first_idx, int64_t cur_pos)
{
  iIndex *i;
  if (cur_pos <= first_idx->pos)
    return 0;

  for (i = first_idx; i != NULL; i = i->next)
  {
    // next iframe pos가 cur pos보다 크면, cur iframe이 가장 가까운 iframe! 
    if (i->next != NULL && i->next->pos >= cur_pos)
      return i->pos;
  }
  // can't find. 
  return 0;
}


iIndex* start_parse_index_file(const char *idx_filename, iIndexHeader *hdr)
{
  FILE *f_idx;
  iIndex* first_iIndex = NULL;
  iIndex* cur_iIndex = NULL;
  f_idx = fopen(idx_filename, "rb");
  if (f_idx == NULL)
  {
		printf("ERROR: Cannot open index file [%s]\n",idx_filename);
		fclose(f_idx);
		return NULL;
  }
  //first parse header
  unsigned char *buf = malloc(sizeof(*hdr));
  if (!buf)
  {
		printf("ERROR: Cannot malloc buf size\n");
		fclose(f_idx);
		return NULL;
  }
  fread(buf, 1, sizeof(*hdr), f_idx);
  memcpy(hdr, buf, sizeof(*hdr));
  free(buf);
  //dump_iIndexHeader(hdr);

  // parse indexes
  unsigned char idx_buf[14];
	size_t NbRead = 0;
	int cnt = 0;
  do {
		NbRead=fread(idx_buf,1,sizeof(idx_buf),f_idx);
		if (NbRead != 14)
		  break;
		cnt++;
    iIndex *idx = malloc(sizeof(*idx));
    idx->next = NULL;
    memcpy(&(idx->pos), idx_buf, 4); 
    memcpy(&(idx->pcr), idx_buf + 4, 6); 
    memcpy(&(idx->frame_num), idx_buf + 10, 4); 
   // dump_iIndex(idx);
   //
    //printf("cnt = %d \n", cnt);
    if (first_iIndex == NULL) {
      //printf("first index == null \n");
      first_iIndex = idx;
      cur_iIndex = idx;
    } else {
      //printf("cur index != null \n");
      cur_iIndex->next = idx;
      cur_iIndex = idx;
    }
    //free(idx);
  } while(NbRead == 14);

  fclose(f_idx);
  return first_iIndex;
}
