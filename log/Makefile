#项目信息

extra_obj_lst = ../msghooker/message_comm.o

objects_list = log.o logclient.o 
EXECS = log.dll
LIBOUT = ../bin/plugin

##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32
pc=$(src_prefix)/lib/pkgconfig

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -I../msghooker -Os
LDFLAGS = -L$(src_prefix)/lib -s -lole32 -lrpcrt4
LIBS = -shared

MAKE = make --no-print-directory
SHELL = /bin/sh

### 具体的编译链接指令 ###

output_name = $(EXECS)

default: $(output_name)

$(output_name): $(objects_list)
	$(LD) -o $(output_name) $(objects_list) $(extra_obj_lst) $(LDFLAGS) $(LIBS)
	mv $(output_name) $(LIBOUT)/$(EXECS)

clean:
	rm -f *.o $(output_name)

.c.o:
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c
