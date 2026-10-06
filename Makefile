CC ?= cc
CFLAGS ?= -O3
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
CPPFLAGS ?=
LDFLAGS ?=

TARGET := ss-rsa-keys
SOURCE := ss-rsa-keys.c

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $@

test: $(TARGET)
	./$(TARGET) --self-test

clean:
	rm -f $(TARGET)
