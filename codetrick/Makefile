#项目信息

objects_list = CodeTrick.o
EXECS = codetrick.dll
LIBOUT = ../bin/plugin
TOOLOUT = ../bin/tool

##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -Os
LDFLAGS = -L$(src_prefix)/lib -s
LIBS = -shared

MAKE = make --no-print-directory
SHELL = /bin/sh

### 具体的编译链接指令 ###

output_name = $(EXECS)

default: $(output_name) dbgstr

$(output_name): $(objects_list)
	$(LD) $(LDFLAGS) -o $(output_name) $(objects_list) $(LIBS)
	mv $(output_name) $(LIBOUT)/$(EXECS)

dbgstr: dbgstr.o
	$(LD) $(LDFLAGS) -o dbgstr.exe dbgstr.o
	mv dbgstr.exe $(TOOLOUT)/dbgstr.exe	

clean:
	rm -f *.o *.exe *.dll

.c.o:
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c
