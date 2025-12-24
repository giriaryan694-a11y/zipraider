# Makefile for ZipRaider-C

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread
LDFLAGS = -lzip -lcrypto
TARGET = zipraider
SRC = zipraider.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

debug:
	$(CC) -g -O0 -Wall -Wextra -pthread -o $(TARGET)_debug $(SRC) $(LDFLAGS)

install:
	cp $(TARGET) /usr/local/bin/

clean:
	rm -f $(TARGET) $(TARGET)_debug *.o

.PHONY: all debug install clean
