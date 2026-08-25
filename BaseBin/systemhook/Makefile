TARGET = systemhook.dylib
CC = clang

CFLAGS = -I../.include -I./src -I../_external/modules/litehook/src -I../_external/include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -install_name @loader_path/$(TARGET) -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -Os -moutline
LDFLAGS = -dynamiclib -L../.build -ljailbreak

sign: $(TARGET)
	@ldid -Cadhoc -S $^

# RootHide port: removed `../libjailbreak/src/roothide_hide.c` (patchwork file deleted).
# Added `../libjailbreak/src/roothider/jailbreakd.c` (Relaxin upstream RootHide jailbreakd client).
$(TARGET): $(wildcard src/*.[cSm] src/common/*.[cSm] ../libjailbreak/src/jbclient_*.c ../libjailbreak/src/inline_svc.[cS] ../libjailbreak/src/hookd.c ../libjailbreak/src/roothider/jailbreakd.c ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
