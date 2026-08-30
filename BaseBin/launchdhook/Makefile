TARGET = launchdhook.dylib
CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -I../.include -I../_external/modules/litehook/src -I../_external/include -Isrc -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -fobjc-arc -O2
# Strip symbols to prevent jailbreak detection via string scanning (see systemhook/Makefile).
LDFLAGS = -dynamiclib -Wl,-S -Wl,-x -rpath @loader_path/fallback -L../.build -L../_external/lib -ljailbreak -lellekit -lbsm -lchoma -lMobileGestalt

sign: $(TARGET)
	@ldid -Cadhoc -S $^

# RootHide port: added `../systemhook/src/roothider_common.c` (Relaxin upstream).
# Keep Kernel-JB's existing `../systemhook/src/common/*.[cSm]` glob (Kernel-JB has common/ subdir; Relaxin has common.c flat).
$(TARGET): $(wildcard src/*.m src/*.c src/jbserver/*.c ../systemhook/src/common/*.[cSm] ../systemhook/src/envbuf.c ../systemhook/src/roothider_common.c ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
