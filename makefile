CC = g++
CFLAGS = -Wall -Wextra -O2
TARGETS = radio-proxy

all: $(TARGETS) 

err.o: err.cpp err.h

radio-proxy.o: radio-proxy.cpp err.h

radio-proxy: radio-proxy.o err.o

clean:
	rm -f *.o $(TARGETS) 
