# Makefile for fastscan: portable, static, cross-compiled
# Usage:
#   make                # Native build
#   make debug          # Debug build
#   CC=arm-linux-gnueabihf-gcc make   # Cross-compile ARM
#   CC=x86_64-w64-mingw32-gcc make    # Cross-compile Windows
#   CFLAGS="-someflags" make          # Custom flags

TARGET ?= fastscan
SRC    := fastscan.c

# Detect OS for platform-specific flags
UNAME_S := $(shell uname -s)
IS_MINGW := $(filter %mingw% %MINGW%,$(CC))
IS_MSVC := $(findstring cl,$(CC))
IS_DARWIN := $(filter Darwin,$(UNAME_S))

# Default CFLAGS
CFLAGS ?= -O2 -Wall

# Static linking (when possible)
ifeq ($(IS_DARWIN),Darwin)
    # macOS: static not supported for system libs
    STATIC_FLAG :=
else ifneq ($(IS_MSVC),)
    # MSVC: /MT for static CRT
    STATIC_FLAG := /MT
else ifneq ($(IS_MINGW),)
    STATIC_FLAG := -static -static-libgcc
else
    STATIC_FLAG := -static
endif

# Windows linking
ifeq ($(IS_MSVC),cl)
    WINLIBS := ws2_32.lib advapi32.lib
else ifneq ($(findstring mingw,$(CC)),)
    WINLIBS := -lws2_32 -ladvapi32
endif

# Output extension
ifeq ($(IS_MSVC),cl)
    EXT := .exe
else ifneq ($(findstring mingw,$(CC)),)
    EXT := .exe
else
    EXT :=
endif

.PHONY: all debug clean

all: $(TARGET)$(EXT)

$(TARGET)$(EXT): $(SRC)
        $(CC) $(CFLAGS) $(STATIC_FLAG) -o $@ $^ $(WINLIBS)

debug: CFLAGS += -g -O0
debug: clean all

clean:
        rm -f $(TARGET) $(TARGET).exe *.o

# Helper for cross-builds:
# CC=arm-linux-gnueabihf-gcc make
# CC=aarch64-linux-gnu-gcc make
# CC=mips-linux-gnu-gcc make
# CC=riscv64-linux-gnu-gcc make
# CC=powerpc-linux-gnu-gcc make
# CC=x86_64-w64-mingw32-gcc make