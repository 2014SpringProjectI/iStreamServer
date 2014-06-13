CC=gcc
CFLAGS=-I.
DEPS= libavutil.a libavcodec.a libavformat.a 
LIBS= -framework QTKit -framework Foundation -framework QuartzCore -framework CoreFoundation -framework VideoDecodeAcceleration -framework QuartzCore -liconv -L/usr/local/lib -lSDLmain -lSDL -Wl,-framework,Cocoa -lxvidcore -lx264 -lvpx -lvpx -lvorbisenc -lvorbis -logg -ltheoraenc -ltheoradec -logg -L/usr/local/Cellar/opus/1.0.3/lib -lopus -lmp3lame -L/usr/local/Cellar/freetype/2.5.0.1/lib -lfreetype -lfdk-aac -L/usr/local/Cellar/libass/0.10.2/lib -lass -lm -lbz2 -lz -pthread
OBJ= iStreamServer.o #libavutil/avssert.o libavutil/avstring.o libavutil/lfg.o libavutil/dict.o libavutil/mathematics.o libavutil/pixdesc.o libavutil/random_seed.o libavutil/parseutils.o libavutil/opt.o libavutil/time.o libavutil/mem.o #libavformat/rtsp.o

I_DEPS = libtsfuncs/libtsfuncs.a

%.o: %.c
	$(CC) -w -c -o $@ $< $(DEPS) $(CFLAGS)

iStreamServer: $(OBJ)
	$(CC) -w -o $@ $^ $(DEPS) $(LIBS) $(CFLAGS)

indexer: iIndexer.c
	$(CC) -w -o $@ $^ $(I_DEPS) $(CFLAGS)

clean: 
	rm -f iStreamServer $(OBJ)
