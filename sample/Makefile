#项目信息
daemon_name = test.exe
daemon_obj_lst = test.o message_comm.o sync_funcs.o

##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32
pc=$(src_prefix)/lib/pkgconfig

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -I../system -I../msghooker -Os
LDFLAGS = -L$(src_prefix)/lib -L../msghooker -s -lole32 -lrpcrt4

fltk-config=$(src_prefix)/bin/fltk-config
CXX = $(bin_prefix)/$(shell $(fltk-config) --cxx)
CXXFLAGS = $(shell $(fltk-config) --use-gl --use-images --cxxflags) $(shell pkg-config --cflags $(pc)/mxml.pc) -I. -Os
CXXLD = $(CXX)
CXXLDFLAGS = $(shell $(fltk-config) --use-gl --use-images --ldstaticflags) $(shell pkg-config --libs $(pc)/mxml.pc) -s -liconv

MAKE = make --no-print-directory
TOOLOUT = ../bin/tool
MAINOUT = ../bin
bin2src = $(TOOLOUT)/bin2src
SHELL = /bin/sh

### 具体的编译链接指令 ###

default: $(daemon_name)

$(daemon_name): $(daemon_obj_lst)
	$(LD) -o $(daemon_name) $(daemon_obj_lst) $(LDFLAGS) 
	mv $(daemon_name) $(TOOLOUT)/$(daemon_name)

clean:
	rm -f *.o *.inc

.c.o:
	$(CC) $(CFLAGS) -c $<

.cxx.o:
	$(CXX) $(CXXFLAGS) -c $<

message_comm.o: ../msghooker/message_comm.c
	$(CC) $(CFLAGS) -c $<

sync_funcs.o: ../system/sync_funcs.c
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c .cxx
