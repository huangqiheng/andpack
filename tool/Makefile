#项目信息

extra_list = ../andpack/log_print.o
objects_list = bin2inc.o bin2head.o
output_name = bin2inc.exe

obj_lst_x11 = bin2src.o bin2head.o
output_name2 = bin2src

all_names = $(output_name) $(output_name2)

LIBOUT = ../bin/tool

##编译器选项

bin_prefix=$(HOME)/mingw-cross-env-2.21/usr/bin
src_prefix=$(HOME)/mingw-cross-env-2.21/usr/i686-pc-mingw32

CC = $(bin_prefix)/i686-pc-mingw32-gcc
LD = $(bin_prefix)/i686-pc-mingw32-gcc
CFLAGS = -I$(src_prefix)/include -Os
LDFLAGS = -L$(src_prefix)/lib -s -mwindows -lcomdlg32 
LIBS = 

MAKE = make --no-print-directory
SHELL = /bin/sh

### 具体的编译链接指令 ###


default: $(all_names)

$(output_name): $(objects_list)
	$(LD) $(LDFLAGS) -o $(output_name) $(objects_list) $(extra_list) $(LIBS)
	mv $(output_name) $(LIBOUT)/$(output_name)
	rm -f *.o 

$(output_name2): 
	gcc -c bin2head.c
	gcc -c bin2src.c
	gcc -o $(output_name2) $(obj_lst_x11)
	mv $(output_name2) $(LIBOUT)/$(output_name2)
	rm -f *.o 

clean:
	rm -f *.o 

.c.o:
	$(CC) $(CFLAGS) -c $<

.SUFFIXES: .c
