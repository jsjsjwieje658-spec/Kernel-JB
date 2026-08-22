TARGET = libjailbreak.dylib

CC = clang

# ROOTHIDE FIX LỖI 2: Added -x objective-c++ for .mm files (Objective-C++)
# This is needed to compile roothide_objc.mm which exports the C++ function
# `jbroot(NSString*)` (mangled: __Z6jbrootP8NSString) that the RootHide
# app (com.roothide.manager) imports at runtime.
#
# Without .mm support, the RootHide app would fail to load with:
#   "Symbol not found: __Z6jbrootP8NSString"
CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -framework IOMobileFramebuffer -framework CoreGraphics -framework ImageIO -lMobileGestalt -I../.include -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -I$(shell brew --prefix)/opt/libarchive/include -D BUILD_STANDALONE=$(BUILD_STANDALONE)
# ROOTHIDE FIX LỖI 2: Added -lc++ (C++ runtime) because roothide_objc.mm is
# compiled as Objective-C++ and references ___gxx_personality_v0 (C++
# exception handling personality routine). Without -lc++, the linker fails
# with: Undefined symbols for architecture arm64: "___gxx_personality_v0"
LDFLAGS = -larchive -lbsm -lc++ -L../.build -F ../_external/frameworks -lchoma

sign: $(TARGET)
	@ldid -Cadhoc -S $<

# ROOTHIDE FIX LỖI 2: Include src/*.mm (Objective-C++ files) in source list
# This compiles roothide_objc.mm which exports the jbroot(NSString*) symbol
# required by the RootHide app.
$(TARGET): $(wildcard src/*.c src/*.m src/*.mm src/*.S ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
