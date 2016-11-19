TARGET = get-rssi
PREFIX = /usr/local

CC = gcc
CFLAGS = -Wall
LDLIBS = -lpcap

SCRS =  main.c   arguments.c  \
	sniff.c  parse_cap.c  \
	./radiotap/radiotap.c
OBJS = $(SCRS:.c=.o)

.PHONY: all clean install uninstall

all:		$(TARGET)

$(TARGET):	$(OBJS)
		$(CC) $(CFLAGS) $(LDLIBS) $(OBJS) -o $(TARGET)
		
.c.o:
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -rf $(TARGET) $(OBJS)

install:
		install $(TARGET) $(PREFIX)/bin
	
uninstall:
		rm -rf $(PREFIX)/bin/$(TARGET)
