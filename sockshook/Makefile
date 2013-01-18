#项目信息
objects_list = parser.o SocksHook.o win32_compatibility.o session_funcs.o crtl_section.o
EXECS = sockshook.dll
LIBOUT = ../bin/plugin

##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -I../system -Os
LDFLAGS = -L$(src_prefix)/lib -s
LIBS = -shared -lws2_32

MAKE = make --no-print-directory
SHELL = /bin/sh

### 具体的编译链接指令 ###

output_name = $(EXECS)

default: $(output_name)

$(output_name): $(objects_list)
	$(LD) $(LDFLAGS) -o $(output_name) $(objects_list) $(LIBS)
	mv $(output_name) $(LIBOUT)/$(EXECS)

clean:
	rm -f *.o $(output_name)

.c.o:
	$(CC) $(CFLAGS) -c $<

session_funcs.o: ../system/session_funcs.c
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c
