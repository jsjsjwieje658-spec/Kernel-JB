TARGET = jailbreakd
DEBUG ?= 0

CC = clang
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS = -Werror -Wno-availability -framework Foundation -framework CoreServices -I../.include -I./src -isysroot $(SDK) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -Wno-nullability-completeness-on-arrays -O3 -DDEBUG=$(DEBUG)
LDFLAGS = -L../.build -ljailbreak -lbsm
SOURCES = $(wildcard src/*.m src/*.c)

all: $(TARGET) sign

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

clean:
	@rm -f $(TARGET)

.PHONY: all clean sign
