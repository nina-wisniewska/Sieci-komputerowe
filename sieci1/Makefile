CC     = g++
CFLAGS = -Wall -Wextra -O2 -Wunused-variable
CXXFLAGS = -Wall -Wextra -O2 -Wunused-variable
LDFLAGS =

.PHONY: all clean

TARGET1 = peer-time-sync

all: $(TARGET1)

$(TARGET1): $(TARGET1).o err.o

peer-time-sync.o: peer-time-sync.cpp err.h
err.o: err.c err.h

clean:
	rm -f $(TARGET1) *.o *~