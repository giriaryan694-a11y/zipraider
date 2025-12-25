# Makefile for ZipRaider-C

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread -D_FILE_OFFSET_BITS=64
LDFLAGS = -lzip -lcrypto
TARGET = zipraider
SRC = zipraider.c

all: $(TARGET)

$(TARGET): $(SRC)
        $(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

debug:
        $(CC) -g -O0 -Wall -Wextra -pthread -D_FILE_OFFSET_BITS=64 -o $(TARGET)_debug $(SRC) $(LDFLAGS) -fsanitize=address

install:
        cp $(TARGET) /usr/local/bin/

clean:
        rm -f $(TARGET) $(TARGET)_debug *.o

test: $(TARGET)
        @echo "Testing basic functionality..."
        ./$(TARGET) -h

.PHONY: all debug install clean test
