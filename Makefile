#Make File for compiling the application automatically
CXX = g++

#compiler Flags
CXXFLAGS = -Wall -g $(shell pcap-config --cflags)

#Link pcacp library with it
LDFLAGS = $(shell pcap-config --libs)

#Application name
TARGET = x_F_R_AssignmentApp

#source file to compile are
SRCS = simpleReadPacketApplication.cpp

#create and object of the source file
OBJS= $(SRCS:.cpp=.o)

#main stuff tell the make to target compile
all: $(TARGET)
$(TARGET):$(OBJS) 
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)
#also rule to make object files from cpp
%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

#clean all the residuals after building of the file
clean:
	rm -f $(OBJS)