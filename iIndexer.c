#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "libtsfuncs/tsfuncs.h"

// ===================================================================
// Universal Indexer for .ts files streamed with Live555 RTSP Server
// Sebastien RAILLARD - COEXSI SARL 2010 - www.coexsi.fr
// ===================================================================

bool isPictureStartCode (unsigned char *buf, int offset)
{
  //return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1 && buf[offset+3] == 0);
  return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1) || (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 0 && buf[offset+3] == 1);
}

bool isPESVideoHeaderCode (unsigned char *buf, int offset)
{
  return (buf[offset] == 0 && buf[offset+1] == 0 && buf[offset+2] == 1 && buf[offset+3] >= 0xE0);
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
	long long unsigned int Packets = 0;
	unsigned int State = 0; // 0=Search PMT 1=Search PCR 2=Search PES
	unsigned int iFrameState = 0; // 0=Search for GOP, 1=Search for iFrame
	unsigned int PCR_PID = 0;
	unsigned int VIDEO_PID = 0;
	double First_PCR = 0;
	double Last_PCR = 0;
	double Index_PCR = 0;
	long long unsigned int PES_Found = 0;
	long long unsigned int PES_HEADER_Found = 0;
	long long unsigned int PES_PICTURE_Found = 0;
	long long unsigned int iFrame_Found = 0;
	long long unsigned int PES_Video_Found = 0;
	long long unsigned int PES_GOP_Found = 0;
	long long unsigned int PES_filtered = 0;
	long long unsigned int PES_ES_Rate_Flag = 0;
	time_t StartTime = time(NULL);
	unsigned char Buffer[188];
	int PESLen = 0;
	struct ts_pat *old_pat = NULL;
  struct ts_pmt *old_pmt = NULL;
  unsigned int PMT_TABLE_PID = 0;
  unsigned int V_STREAM_PID = 0;
  unsigned int V_TYPE = 264; // 264 = h264, 265 = h265

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
	}
	
	// Loop
	printf("Searching the first PSI-PMT packet...\n");
	do
	{
		// Read the next TS packet and check its size
		NbRead=fread(Buffer,1,sizeof(Buffer),sr);
		
		if (NbRead==188)
		{
			// Starting TS packet analysis
			Packets++;
			
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

      struct ts_header *ts_header = malloc(sizeof(*ts_header));
      ts_packet_header_parse(Buffer, ts_header);
      /*
      ts_packet_header_dump(ts_header);
      struct ts_section_header *ts_sec_header = ts_section_data_alloc();
      ts_section_header_parse(Buffer, ts_header, ts_sec_header);
      ts_section_dump(ts_sec_header);
      */

      if (PID == V_STREAM_PID) {
       int offset = ts_header->payload_offset;
       for (int i=0; offset+i+4<188; i++) {
        if(isPictureStartCode(Buffer, offset+i)) {
          //printf("It's picture header! offset = %d \n", offset+i+5);
          PES_PICTURE_Found++;
          //unsigned char type = ((Buffer[offset+5+i] & 0x38) >> 3);
          if (V_TYPE == 264) {
            unsigned char type = Buffer[offset+i+2] == 1 ? (Buffer[offset+3+i] & 0x1f) : (Buffer[offset+4+i] & 0x1f);
            if (type == 5) { 
              printf("picture type = %u \n", type);
              iFrame_Found++;
              printf("i frame found!!! \n");
            }
          } else if (V_TYPE == 265) {
            unsigned char type = Buffer[offset+i+2] == 1 ? (Buffer[offset+3+i] & 0x7e) : (Buffer[offset+4+i] & 0x7e);
            // 16,17,18 - BLA , 19,20 IDR, 21 CRA
            if (type >= 16 && type <= 21) { 
              printf("picture type = %u \n", type);
              iFrame_Found++;
              printf("i frame found!!! \n");
            }
          }
        }
       }
      }
      //get pes
      //for(int i=ts_header->payload_offset; i<188-3; i++) {
        if (isPESVideoHeaderCode(Buffer, ts_header->payload_offset)) {
          PES_HEADER_Found++;
          struct ts_pes *ts_pes = ts_pes_alloc();
          ts_pes_push_packet(ts_pes, Buffer, old_pmt, PID); 
          //ts_pes_dump(ts_pes);
          if (ts_pes->ES_rate_flag > 0) {
            printf("Es rate flag = %d \n", ts_pes->ES_rate_flag);
            printf("Es rate = %d bytes/sec\n", ts_pes->ES_rate * 50);
          }
          ts_pes_free(&ts_pes);
        }
      //}
      free(ts_header);

      // get pat table 
      if (PID == 0) {
        struct ts_pat *ts_pat = ts_pat_alloc();
        ts_pat_push_packet(ts_pat, Buffer);
        if (!ts_pat_is_same(old_pat, ts_pat)) {
          old_pat = ts_pat_copy(ts_pat);
          ts_pat_dump(ts_pat);
          PMT_TABLE_PID = old_pat->programs[0]->pid;
        } 
        ts_pat_free(&ts_pat);
      }
      // get pmt 
      if (PMT_TABLE_PID != 0 && PMT_TABLE_PID == PID) {
        struct ts_pmt *ts_pmt = ts_pmt_alloc();
        ts_pmt_push_packet(ts_pmt, Buffer);
        if (!ts_pmt_is_same(old_pmt, ts_pmt)) {
          old_pmt = ts_pmt_copy(ts_pmt);
          ts_pmt_dump(ts_pmt);
          for(int i=0; i<ts_pmt->streams_num; i++) {
            printf("stream type = %x \n", ts_pmt->streams[i]->stream_type);
            if(ts_pmt->streams[i]->stream_type == 0x1B) {
              printf("it's H.264 Video \n");
              V_TYPE = 264;
              V_STREAM_PID = ts_pmt->streams[i]->pid;
            } else if (ts_pmt->streams[i]->stream_type == 0x24) {
              V_TYPE = 265;
              printf("it's H.265 Video \n");
              V_STREAM_PID = ts_pmt->streams[i]->pid;
            }
            printf("stream pid = %x \n", ts_pmt->streams[i]->pid);
            printf("ES_info_size = %d \n", ts_pmt->streams[i]->ES_info_size);
          }
        } 
        ts_pmt_free(&ts_pmt);
      }

      if (PID == 1) {
        printf(" It's transport stream description table!!! \n");
      }

		  if (PID == PCR_PID) {
        if ((Buffer[3] & 0x20 ) && (Buffer[4] > 0)) {
          if (Buffer[5] & 0x40) {
            // found keyframe! 
            //iFrame_Found++;
            //printf("keyframe found!!! \n");
          }
        }
      }


			// Searching PMT
			if (State == 0)
			{
				// TS values checking
				if (transport_error_indicator == 0 && payload_unit_start_indicator == 1 && PID != 0x1FFF && transport_scrambling_control == 0 && adaptation_field_control == 1)
				{
					// Checking if it's not a PES - No packet_start_code_prefix
					if (!(Buffer[4] == 0 && Buffer[5] == 0 && Buffer[6] == 1))
					{
						// Checking if there is PSI table signature with table_id=2 for PMT and we assume the pointer_field=0 (maybe not always true...)
						// http://www.etherguidesystems.com/help/sdos/mpeg/syntax/tablesections/pmts.aspx, PCR_PID has 67 offset bits , # of bits 13 
						if (Buffer[4] == 0 && Buffer[5] == 2 && (Buffer[6] & 0xC0) == 0x80)
						{
							// Ok, we have the PMT, we need will get the PCR PID and assume that it is the Video PID
							printf(" * PMT PID is %d (0x%X) - %llu Packets skipped since beginning\n",PID,PID,(Packets - 1));
							// TS header 4 bytes + offset 67bits, Buffer[13]의 앞3bits 빼고 4번재 bits ~ Buffer[14]값. 
							PCR_PID = (((unsigned int)Buffer[13] & 0x1F) << 8) + (unsigned int)Buffer[14];
							printf(" * PCR PID is %d (0x%X) - We assume it is also the video PID\n",PCR_PID,PCR_PID);
							// Next, we search the first PCR
							State = 1;
							printf("Searching the first PCR...\n");
						}
					} else {
					  printf("State 0, We met PES Header!! \n ");
          }
				}
			}
			
			// Searching the PCR
			if (State == 1 || State == 2)
			{
				// Checking some TS values - Looking for PCR PID with adpation field
				if (PID == PCR_PID && transport_error_indicator == 0 && (adaptation_field_control == 2 || adaptation_field_control == 3))
				{
					// Checking if adpation field length is not nul and if PCR flag is set
					// Buffer[4] is adaption length. Buffer[5]의 뒤 5바이트가 optional fields flags.  Buffer[5]의 4번째 비트가 PCR indicator! 
					if (Buffer[4] > 0 && (Buffer[5] & 0x10) == 0x10)
					{
						// Getting the raw PCR values
						// PCR_Base is 33bits. PCR_Ext is 9bits 
						unsigned long long int PCR_Base = ((unsigned long long int)Buffer[6] << 25) + ((unsigned long long int)Buffer[7] << 17) + ((unsigned long long int)Buffer[8] << 9) + ((unsigned long long int)Buffer[9] << 1) + (((unsigned long long int)Buffer[10] & 0x80) >> 7);
						unsigned long long int PCR_Ext = (((unsigned long long int)Buffer[10] & 0x1) << 8) + (unsigned long long int)Buffer[11];
						// Transforming to double (float isn't big enough!)
						Last_PCR = ((double)PCR_Base / 90000.0f) + ((double)PCR_Ext / 27000000.0f);
						// Check if we were searching the first PCR
						if (State == 1)
						{
							// We start indexing
							State = 2;
							First_PCR = Last_PCR;
							printf(" * First PCR value is %.3fs - %llu Packets skipped since beginning\n",First_PCR,(Packets - 1));
							printf("Searching PES sections start for indexing...\n");
						}
					}

          // Adaption Field 뒤에 PES Header가 있는지 체크! 
          if (transport_error_indicator == 0 && payload_unit_start_indicator == 1 && adaptation_field_control == 3)
          {
            unsigned char adaptation_field_length = Buffer[4];
            // Checking if it's PES
            if (Buffer[4 + adaptation_field_length] == 0 && Buffer[5 + adaptation_field_length] == 0 && Buffer[6 + adaptation_field_length] == 1)
            {
              printf(" Includeing PCR TS packet Also had PES header in payload!!! \n");
            }
          }
				}
				// check This TS packet is Contains PES header in payload! 
				// adaptation_field_control == 2이면 no payload. adaptation only!
			}
			
			// Indexing 
			if (State == 2)
			{
				if (transport_error_indicator == 0 && payload_unit_start_indicator == 1 && PID != 0x1FFF && transport_scrambling_control == 0 && adaptation_field_control == 1)
				{
					// Checking if it's a PES
					if ((Buffer[4] == 0 && Buffer[5] == 0 && Buffer[6] == 1))
					{
            //PES_HEADER_Found++;
            if (Buffer[7] >= 0xE0) {
              //PES_Video_Found++;
              // get PES Header length 
              int pes_packet_length = (Buffer[8] << 4) + Buffer[9];
             // printf("pes_packet_length = %d\n", pes_packet_length);
              unsigned char es_rate_flag = (Buffer[11] & 0x10) >> 4;
              if (es_rate_flag == 1)
                PES_ES_Rate_Flag++;
              
              /*
              int pes_header_length = Buffer[12];
             // printf("pes_headr_length = %d\n", pes_header_length);
              if (pes_header_length != 128) {
                printf("pes header lenght isnt 128!! \n");
                break;
              }
             // pes header length is 128! 
             int offset = 12 + pes_header_length;

             for (int i=0; offset+i+3<188; i++) {
               if (isGOPstartCode(Buffer, offset+i)) {
                 printf("is start of GOP! \n");
                 PES_GOP_Found++;
               }
               if (offset+i+5 < 188) {
                if(isPictureStartCode(Buffer, offset+i)) {
                  //printf("It's picture header! offset = %d \n", offset+i+5);
                  PES_PICTURE_Found++;
                  //unsigned char type = ((Buffer[offset+5+i] & 0x38) >> 3);
                  unsigned char type = Buffer[offset+i+2] == 1 ? (Buffer[offset+3+i] & 0x1f) : (Buffer[offset+4+i] & 0x1f);
                  if (type == 5) { 
                    printf("picture type = %u \n", type);
                    iFrame_Found++;
                    printf("i frame found!!! \n");
                  }
                }
               }
             }
              */

             /*

             PESLen = 188-offset;

             do {
              PESLen += fread(Buffer,1,sizeof(Buffer),sr) - 4;
              //printf("find gop or iframe in PES data pes len = %d, pes_packet_len = %d\n", PESLen, pes_packet_length);
              Packets++;
              unsigned char sync_byte = Buffer[0];
              unsigned char transport_error_indicator = (Buffer[1] & 0x80) >> 7;
              unsigned char payload_unit_start_indicator = (Buffer[1] & 0x40) >> 6;
              unsigned int PID = (((unsigned int)Buffer[1] & 0x1F) << 8) + (unsigned int)Buffer[2];
              unsigned char transport_scrambling_control = (Buffer[3] & 0xC0) >> 6;
              unsigned char adaptation_field_control = (Buffer[3] & 0x30) >> 4;
              if (sync_byte!=0x47) 
              {
                printf("ERROR: Missing the TS sync byte!\n");
                break;
              }

               int offset = 4;
               for (int i=0; offset + i + 3 < 188; i++) {
                 if (isGOPstartCode(Buffer, offset+i)) {
                   printf("is start of GOP! \n");
                   PES_GOP_Found++;
                 }
                 if (offset+i+5 < 188) {
                  if(isPictureStartCode(Buffer, offset+i)) {
                    PES_PICTURE_Found++;
                   // printf("It's picture header! offset = %d \n", offset+i+5);
                    unsigned char type = ((Buffer[offset+5+i] & 0x38) >> 3);
                    printf("picture type = %u \n", type);
                    if (type == 1) { 
                      iFrame_Found++;
                      printf("i frame found!!! \n");
                    }
                    break;
                  }
                 }
                 break;
               }
            } while(PESLen+184<=pes_packet_length);
            */

            }

          }
				}

				// Checking some TS values - Looking for PCR PID with start section
				if (PID == PCR_PID && transport_error_indicator == 0 && payload_unit_start_indicator == 1)
				{
					// We certainly have a PES section start here
					PES_Found++;
					// Check if we have a new PCR
					if (Index_PCR != Last_PCR)
					{
						// We keep the value for the next check
						Index_PCR = Last_PCR;
						// We create an index
						unsigned char Index[11];
						Index[0] = 0x81; // RECORD_VSH / First record of frame
						Index[1] = 0; // No start offset information
						Index[2] = 0; // No payload size information
						// PCR transformation - Starting at 0
						unsigned long long int PCR_Int = (unsigned long long int)(Last_PCR - First_PCR); // Truncate float to integer
						Index[3] = (unsigned char)(PCR_Int & 0xFF);
						Index[4] = (unsigned char)((PCR_Int & 0xFF00) >> 8);
						Index[5] = (unsigned char)((PCR_Int & 0xFF0000) >> 16);
						unsigned char PCR_Frac = (unsigned char)(((Last_PCR - First_PCR) - (double)(PCR_Int)) * 255.0f);
						Index[6] = PCR_Frac;
						// TS packet number - Starting at 1
						Index[7] = (unsigned char)(Packets & 0xFF);
						Index[8] = (unsigned char)((Packets & 0xFF00) >> 8);
						Index[9] = (unsigned char)((Packets & 0xFF0000) >> 16);
						Index[10] = (unsigned char)((Packets & 0xFF000000) >> 24);
						// Writing the index
						//fwrite(Index,1,sizeof(Index),sw);
					}
					else
					{
						// We filter this PES (no PCR update)
						PES_filtered++;
					}
				}
			}

		}

		if (NbRead>0 && NbRead<188)
		{
			// Check if we have a uncommon read size
			printf("WARNING: The file doesn't contain an exact number of TS packets!\n");
		}
	}
	while(NbRead==188);
	
	// Closing files
	fclose(sr);
	fclose(sw);
	
	// Show stats
	printf(" * %llu TS packets were read\n",Packets);
	printf(" * %llu PES sections were found\n",PES_Found);
	printf(" * %llu PES_HEADER sections were found\n",PES_HEADER_Found);
	printf(" * %llu PES_Video sections were found\n",PES_Video_Found);
	printf(" * %llu PES_GOP sections were found\n",PES_GOP_Found);
	printf(" * %llu PES_Picture sections were found\n",PES_PICTURE_Found);
	printf(" * %llu iFrame sections were found\n",iFrame_Found);
	printf(" * %llu PES sections were filtered\n",PES_filtered);
	printf(" * %llu PES ES Rate Flags were found\n",PES_ES_Rate_Flag);
	// test 
	/*
	unsigned char Buf[10];
	Buf[0] = 0;
	Buf[1] = 0;
	Buf[2] = 1;
	Buf[3] = 0;
	if (isPictureStartCode(Buf, 0))
	  printf("isGOP start code!!! \n");
	// test end 
	*/
	if (First_PCR > 0 && Last_PCR > 0)
	{
		printf(" * Last PCR value is %.3fs\n",Last_PCR);
		printf(" * Movie length estimation is %.3fs\n",(Last_PCR - First_PCR));
	}
	printf(" * Indexing running time was %.0fs\n",difftime(time(NULL),StartTime));

	// End
	printf("End of indexing.\n");
	return(0);
}
