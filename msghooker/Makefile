#项目信息
daemon_name = daemon.exe
daemon_obj_lst = daemon_exe.o global.o dll_in_section.o message_comm.o sync_funcs.o

stub_name = stub.exe
stub_obj_lst = stub_exe.o global.o dll_in_section.o package.o list.o message_comm.o xml_in_section.o sync_funcs.o

session_name = session.dll
session_obj_lst = session_dll.o dll_in_section.o global.o dll_loader.o stackar.o threadpower.o message_comm.o xml_in_section.o sync_funcs.o

packer_name = packer.dll
packer_obj_lst = packer_dll.o global.o dll_in_section.o dll_loader.o package.o list.o message_comm.o sync_funcs.o

copack_name = copack.exe
copack_obj_lst = copack_exe.o global.o copack.o package.o dll_in_section.o list.o queue.o stackar.o message_comm.o xml_in_section.o sync_funcs.o


##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32
pc=$(src_prefix)/lib/pkgconfig

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -I../system $(shell pkg-config --cflags $(pc)/mxml.pc) -Os
LDFLAGS = -L$(src_prefix)/lib -s $(shell pkg-config --libs $(pc)/mxml.pc) -lole32 -lrpcrt4

fltk-config=$(src_prefix)/bin/fltk-config
CXX = $(bin_prefix)/$(shell $(fltk-config) --cxx)
CXXFLAGS = $(shell $(fltk-config) --use-gl --use-images --cxxflags) $(shell pkg-config --cflags $(pc)/mxml.pc) -I. -I../system -Os
CXXLD = $(CXX)
CXXLDFLAGS = $(shell $(fltk-config) --use-gl --use-images --ldstaticflags) $(shell pkg-config --libs $(pc)/mxml.pc) -s -liconv -lole32 -lrpcrt4

MAKE = make --no-print-directory
TOOLOUT = ../bin/tool
MAINOUT = ../bin
bin2src = $(TOOLOUT)/bin2src
SHELL = /bin/sh

### 具体的编译链接指令 ###

default: $(daemon_name) $(stub_name) $(session_name) $(packer_name) $(copack_name)

$(daemon_name): $(daemon_obj_lst)
	$(LD) -o $(daemon_name) $(daemon_obj_lst) $(LDFLAGS) 
	$(bin2src) ./$(daemon_name) ./$(daemon_name).inc
	mv $(daemon_name) $(TOOLOUT)/$(daemon_name)

$(stub_name): $(stub_obj_lst)
	$(LD) -o $(stub_name) $(stub_obj_lst) $(LDFLAGS) -mwindows 
	$(bin2src) ./$(stub_name) ./$(stub_name).inc
	mv $(stub_name) $(TOOLOUT)/$(stub_name)

$(session_name): $(session_obj_lst)
	$(LD) -o $(session_name) $(session_obj_lst) $(LDFLAGS) -shared
	$(bin2src) ./$(session_name) ./$(session_name).inc
	mv $(session_name) $(TOOLOUT)/$(session_name)

$(packer_name): $(packer_obj_lst)
	$(LD) -o $(packer_name) $(packer_obj_lst) $(LDFLAGS) -shared
	$(bin2src) ./$(packer_name) ./$(packer_name).inc
	mv $(packer_name) $(TOOLOUT)/$(packer_name)

$(copack_name): $(copack_obj_lst)
	$(CXXLD) -o $(copack_name) $(copack_obj_lst) $(CXXLDFLAGS)
	mv $(copack_name) $(MAINOUT)/$(copack_name)

clean:
	rm -f *.o *.inc

.c.o:
	$(CC) $(CFLAGS) -c $<

.cxx.o:
	$(CXX) $(CXXFLAGS) -c $<

sync_funcs.o: ../system/sync_funcs.c
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c .cxx
