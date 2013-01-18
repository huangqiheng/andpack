output_path = ../bin/plugin

mingwusr=$(HOME)/mingw-cross-env-2.21/usr
mingwbin=$(mingwusr)/bin
mingwgcc=$(mingwusr)/i686-pc-mingw32/bin

fltk-config=$(mingwgcc)/fltk-config
curl-config=$(mingwgcc)/curl-config

CXX = $(mingwbin)/$(shell $(fltk-config) --cxx)
DEBUG = 
CXXFLAGS = $(shell $(fltk-config) --use-gl --use-images --cxxflags) $(shell $(curl-config) --cflags) -I. -Os
LDFLAGS = $(shell $(fltk-config) --use-gl --use-images --ldflags) 
LDSTATIC = $(shell $(fltk-config) --use-gl --use-images --ldstaticflags) $(shell $(curl-config) --libs) -lpthread -shared -s
LINK = $(CXX)

TARGET = socksui.dll
OBJS = srvlist.o main.o
SRCS = srvlist.cxx main.cxx

.SUFFIXES: .o .cxx
%.o: %.cxx
	$(CXX) $(CXXFLAGS) $(DEBUG) -c $<

all: $(TARGET)
	$(LINK) -o $(TARGET) $(OBJS) $(LDSTATIC)
	mv $(TARGET) $(output_path)

$(TARGET): $(OBJS)
main.o: main.cxx srvlist.h
srvlist.o: srvlist.cxx srvlist.h

.PHONY : clean
clean: 
	rm -f *.o 2> /dev/null
	rm -f $(TARGET) 2> /dev/null
