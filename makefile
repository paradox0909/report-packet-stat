CC=gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-lpcap

SRCS=packet-stat.c
OBJS=$(SRCS:.c=.o)
TARGET=packet-stat

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(TARGET) $(OBJS)
