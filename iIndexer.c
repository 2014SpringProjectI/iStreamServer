#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "libtsfuncs/tsfuncs.h"
#include "iIndexParser.h"

// ===================================================================
// Universal Indexer for .ts files streamed with Live555 RTSP Server
// Sebastien RAILLARD - COEXSI SARL 2010 - www.coexsi.fr
// ===================================================================
//

typedef struct {
  unsigned int total_length; // total # of ts packets
  unsigned int bit_rate; // kbps 
  unsigned char encoding_format; // 0 == h264, 1 == h265
  unsigned int duration; // seconds 
} index_header;

bool isPictureStartCode (unsigned char *buf, int offset)
{
  return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1);
  //return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1) || (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 0 && buf[offset+3] == 1);
}

bool isPESVideoHeaderCode (unsigned char *buf, int offset)
{
  return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1 && buf[offset+3] >= 0xE0);
}

void write_index(FILE *sw, unsigned char *PCR, unsigned int packet_offset, unsigned int frame_num)
{
  // We create an index
  unsigned char Index[14];
  // Pos of iFrame
  memcpy(Index, &packet_offset, 4);
  memcpy(Index+4, PCR, 6);
  memcpy(Index+10, &frame_num, 4);
  // Writing the index
  fwrite(Index,1,sizeof(Index),sw);
}
// Main entry point
int main(int argc, char const** argv) 
{
	// Test parameter count
	if (argc!=2)
	{
		printf("ERROR: One input .ts file must be specified as parameter!\n");
		return(1);
	}
	char const* FileName = argv[1];

	// Test if file exists
	struct stat info;
	if (stat(FileName,&info)!=0)
	{
		printf("ERROR: Input file [%s] doesn't exist!\n",FileName);
		return(1);
	}
	
	// Check whether the input file name ends with ".ts":
	int len = strlen(FileName);
	if (len<4 || strcmp(&FileName[len-3], ".ts") != 0)
	{
		printf("ERROR: Input file [%s] isn't a .ts file!\n",FileName);
		return(1);
	}
	
	// Create index file name .ts => .tsx
	char* IndexName;
	asprintf(&IndexName, "%sx", FileName);
	
	// Infos
	printf("Starting indexing of [%s]\n",FileName);
	printf("Index file created will be [%s]\n",IndexName);
	
	// Some variables declaration
	// long long unsigned int = uint64 
	// unsigned int = uint32
	size_t NbRead = 0;
	unsigned int Packets = 0;
	unsigned int PCR_Found_Pos = 0; // last_pcr_find pos, byte pos mean : 188 * pcr_found_pos
	unsigned int State = 0; // 0=Search PMT 1=Search PCR 2=Search PES
	unsigned int iFrameState = 0; // 0=Search for GOP, 1=Search for iFrame
	unsigned int PCR_PID = 0;
	double First_PCR = 0;
	double Last_PCR = 0;
	double Index_PCR = 0;
	unsigned char Last_PCR_BYTES[6];
	long long unsigned int PES_Found = 0;
	long long unsigned int PES_HEADER_Found = 0;
	long long unsigned int PES_PICTURE_Found = 0;
	unsigned int iFrame_Found = 0;
	long long unsigned int PES_Video_Found = 0;
	long long unsigned int PES_filtered = 0;
	time_t StartTime = time(NULL);
	unsigned char Buffer[188];
	int PESLen = 0;
	struct ts_pat *old_pat = NULL;
  struct ts_pmt *old_pmt = NULL;
  unsigned int PMT_TABLE_PID = 0;
  unsigned int V_STREAM_PID = 0;
  unsigned int V_TYPE = 264; // 264 = h264, 265 = h265
  unsigned int NUM_OF_WRITE = 0;
  index_header *hdr;

	// Opening files
	FILE *sr;
	sr = fopen(FileName,"rb");
	if (sr==NULL)
	{
		printf("ERROR: Cannot open source file [%s]!\n",FileName);
		return(1);
	}
	FILE *sw;
	sw = fopen(IndexName,"wb");
	if (sw==NULL)
	{
		printf("ERROR: Cannot open index file [%s]!\n",IndexName);
		fclose(sr);
		return(1);
	} else {
	  // write header
    hdr = malloc(sizeof(*hdr)); 
    if (!hdr) {
      printf("ERROR: Cannot malloc hdr\n");
      return(1);
    }
    unsigned char IndexHeader[sizeof(*hdr)]; 
    memcpy(IndexHeader, hdr, sizeof(*hdr));
    fwrite(IndexHeader,1,sizeof(IndexHeader),sw);
  }
	
	// Loop
	printf("Searching the first PSI-PMT packet...\n");
	do
	{
		// Read the next TS packet and check its size
		NbRead=fread(Buffer,1,sizeof(Buffer),sr);
		
		if (NbRead==188)
		{
			// General TS values
			unsigned char sync_byte = Buffer[0];
			unsigned char transport_error_indicator = (Buffer[1] & 0x80) >> 7;
			unsigned char payload_unit_start_indicator = (Buffer[1] & 0x40) >> 6;
			unsigned int PID = (((unsigned int)Buffer[1] & 0x1F) << 8) + (unsigned int)Buffer[2];
			unsigned char transport_scrambling_control = (Buffer[3] & 0xC0) >> 6;
			unsigned char adaptation_field_control = (Buffer[3] & 0x30) >> 4;

			// Check if the sync byte is present
			if (sync_byte!=0x47) 
			{
				printf("ERROR: Missing the TS sync byte!\n");
				NbRead = 0;
			}
			
					// find h.264 random access indicator 


      // get pat table 
      /*
      if (State == 0) 
      {
      */
        if (PID == 0) 
        {
          struct ts_pat *ts_pat = ts_pat_alloc();
          ts_pat_push_packet(ts_pat, Buffer);
          if (!ts_pat_is_same(old_pat, ts_pat)) {
            old_pat = ts_pat_copy(ts_pat);
            ts_pat_dump(ts_pat);
            PMT_TABLE_PID = old_pat->programs[0]->pid;
            printf(" * PMT PID is %u (0x%X) - %u Packets skipped since beginning\n",PMT_TABLE_PID,PMT_TABLE_PID,(Packets - 1));
          } 
          ts_pat_free(&ts_pat);
        }
        // get pmt 
        if (PMT_TABLE_PID != 0 && PMT_TABLE_PID == PID) 
        {
          struct ts_pmt *ts_pmt = ts_pmt_alloc();
          ts_pmt_push_packet(ts_pmt, Buffer);
          if (!ts_pmt_is_same(old_pmt, ts_pmt)) {
            old_pmt = ts_pmt_copy(ts_pmt);
            ts_pmt_dump(ts_pmt);
            PCR_PID = ts_pmt->PCR_pid;
            printf(" * PCR PID is %d (0x%X)\n",PCR_PID,PCR_PID);
            for(int i=0; i<ts_pmt->streams_num; i++) {
              printf("stream type = %x \n", ts_pmt->streams[i]->stream_type);
              if(ts_pmt->streams[i]->stream_type == 0x1B) 
              {
                printf("it's H.264 Video \n");
                V_TYPE = 264;
                V_STREAM_PID = ts_pmt->streams[i]->pid;
              } else if (ts_pmt->streams[i]->stream_type == 0x24) 
              {
                V_TYPE = 265;
                printf("it's H.265 Video \n");
                V_STREAM_PID = ts_pmt->streams[i]->pid;
              }
            }
            printf("Video stream stream pid = %d, (0x%X) \n", V_STREAM_PID, V_STREAM_PID);
            State = 1; // go to next step!
          } 
          ts_pmt_free(&ts_pmt);
        }
      //}
			
			// Searching the PCR
			if (State == 1 || State == 2)
			{
				// GET PCR!
				if (PID == PCR_PID)
				{
          // parse pcr if exist
          if (ts_packet_has_pcr(Buffer))  
          {
            PCR_Found_Pos = Packets;
            uint64_t pcr_base = 0;
            uint16_t pcr_ext = 0;
            uint64_t pcr = ts_packet_get_pcr_ex(Buffer, &pcr_base, &pcr_ext);
            double New_PCR = ((double)pcr_base / 90000.0f) + ((double)pcr_ext/27000000.0f); 
            memcpy(Last_PCR_BYTES, Buffer+6, 6);
            if (First_PCR == 0)
              First_PCR = New_PCR;
            else if(Last_PCR != New_PCR)
              Last_PCR = New_PCR;
            else {
              // Last PCR == New_PCR 
              // PCR과 PCR 사이에 iFrame 을 못찾음!!!! 
              printf("Can't find iFrame between PCRs \n");
            }
            //printf("It has pcr!! %lld %.3fs\n", pcr, ((double)pcr_base / 90000.0f) + ((double)pcr_ext/27000000.0f));
            State = 2; // finding i Frame pos!
          }
        }
      }

      // Searching the IDR Frame
      if (State == 2) 
      {
        if (PID == V_STREAM_PID) 
        {
          struct ts_header *ts_header = malloc(sizeof(*ts_header));
          ts_packet_header_parse(Buffer, ts_header);
          int offset = ts_header->payload_offset;
          for (int i=0; offset+i+4<188; i++) {
            if(isPictureStartCode(Buffer, offset+i)) 
            {
              //printf("It's picture header! offset = %d \n", offset+i+5);
              PES_PICTURE_Found++;
              //unsigned char type = ((Buffer[offset+5+i] & 0x38) >> 3);
              if (V_TYPE == 264) 
              {
                unsigned char type = Buffer[offset+i+2] == 1 ? (Buffer[offset+3+i] & 0x1f) : (Buffer[offset+4+i] & 0x1f);
                if (type == 5) 
                { 
                  printf("picture type = %u \n", type);
                  iFrame_Found++;
                  printf("i frame found!!! Packet Num = %u diff from pcr = %u\n", Packets, Packets - PCR_Found_Pos);
                  printf("PCR =  %.3fs\n", Last_PCR);
                  State = 1; // write index 
                  NUM_OF_WRITE++;
                  write_index(sw, Last_PCR_BYTES, PCR_Found_Pos, iFrame_Found);
                }
              } else if (V_TYPE == 265) {
                unsigned char type = Buffer[offset+i+2] == 1 ? (Buffer[offset+3+i] & 0x7e) >> 1 : (Buffer[offset+4+i] & 0x7e) >> 1;
                // 16,17,18 - BLA , 19,20 IDR, 21 CRA
                if (type >= 16 && type <= 21) { 
                  printf("picture type = %u \n", type);
                  iFrame_Found++;
                  printf("i frame found!!! Packet Num = %u diff from pcr = %u\n", Packets, Packets - PCR_Found_Pos);
                  printf("PCR =  %.3fs\n", Last_PCR);
                  State = 1; // write index 
                  NUM_OF_WRITE++;
                  write_index(sw, Last_PCR_BYTES, Packets, iFrame_Found);
                }
              } // end else if 
            } // end if 
          } // end for 
          free(ts_header);
        } // end if 
			} // end state 2 

      // write index to tsx file
			// Starting TS packet analysis
			Packets++;
		}

		if (NbRead>0 && NbRead<188)
		{
			// Check if we have a uncommon read size
			printf("WARNING: The file doesn't contain an exact number of TS packets!\n");
		}
	}
	while(NbRead==188);
	unsigned int duration = (unsigned int)(Last_PCR - First_PCR);
	double total_length = Packets * 188; // (bytes)
	unsigned int bit_rate = (unsigned int)((total_length / duration) * 8.0f / 1000.0f); // kbps
	hdr->total_length = Packets;
	hdr->bit_rate = (unsigned int)bit_rate;
	hdr->encoding_format = V_TYPE == 264 ? 0 : 1;
	hdr->duration = duration;
  unsigned char IndexHeader[sizeof(*hdr)]; 
  memcpy(IndexHeader, hdr, sizeof(*hdr));
  free(hdr);
  // rewrite header
  // fp 파일의 처음으로 위치시키고, header settting
  fseek(sw, 0, SEEK_SET);
  fwrite(IndexHeader,1,sizeof(IndexHeader),sw);
	
	// Closing files
	fclose(sr);
	fclose(sw);
  
  // for test
  iIndexHeader *i_hdr = malloc(sizeof(*i_hdr));
	iIndex *first_idx = start_parse_index_file(IndexName, i_hdr);
	//dump_iIndexHeader(i_hdr);
	//dump_through_iIndex(first_idx);
	free(i_hdr);
	// test end 
	
	// Show stats
	printf(" * %u TS packets were read\n",Packets);
	printf(" * %llu PES sections were found\n",PES_Found);
	printf(" * %llu PES_Video sections were found\n",PES_Video_Found);
	printf(" * %llu PES_Picture sections were found\n",PES_PICTURE_Found);
	printf(" * %u iFrame sections were found\n",iFrame_Found);
	printf(" * %llu PES sections were filtered\n",PES_filtered);
	printf(" * %u Num of write\n",NUM_OF_WRITE);
	if (First_PCR > 0 && Last_PCR > 0)
	{
		printf(" * Last PCR value is %.3fs\n",Last_PCR);
		printf(" * Movie length estimation is %.3fs\n",(Last_PCR - First_PCR));
		printf(" * Movie length estimation is %us\n", duration);
		printf(" * bit_rate is %.ukbps\n", bit_rate);
	}
	printf(" * Indexing running time was %.0fs\n",difftime(time(NULL),StartTime));

	// End
	printf("End of indexing.\n");
	return(0);
}
