TARGET = libjailbreak.dylib

CC = clang

# RootHide port: build the roothider/ subdirectory (Relaxin upstream fork) into libjailbreak.dylib.
# The old flat roothide.{c,h}, roothide_objc.mm, roothide_hide.c files have been removed.
# The upstream canonical header at _external/include/roothide.h declares jbroot()/rootfs()/jbrand()
# which are provided by libroothide.dylib at runtime (from RootHide bootstrap).
CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -framework IOMobileFramebuffer -framework CoreGraphics -framework ImageIO -lMobileGestalt -I../.include -I../_external/modules/litehook/src -I../_external/include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -I$(shell brew --prefix)/opt/libarchive/include -D BUILD_STANDALONE=$(BUILD_STANDALONE)
# -lc++ is required for the C++ files in src/roothider/ (blacklist.cpp uses C++ STL).
# Strip symbols to prevent jailbreak detection via string scanning (see systemhook/Makefile).
LDFLAGS = -Wl,-S -Wl,-x -larchive -lbsm -lc++ -L../.build -F ../_external/frameworks -lchoma

CORE_SOURCES = $(wildcard src/*.c src/*.m src/*.S)
ROOTHIDER_SOURCES = $(wildcard src/roothider/*.c src/roothider/*.m src/roothider/*.cpp)

sign: $(TARGET)
	@ldid -Cadhoc -S $<

# Build with: core libjailbreak sources + roothider/ subdirectory + litehook external module.
$(TARGET): Makefile $(CORE_SOURCES) $(ROOTHIDER_SOURCES) $(wildcard ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(filter-out Makefile,$^)

clean:
	@rm -f $(TARGET)
