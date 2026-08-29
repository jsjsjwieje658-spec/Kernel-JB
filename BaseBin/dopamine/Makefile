TARGET = dopamine

CC = clang

CHOMA_CFLAGS = -DDISABLE_SIGNING=1
XPF_CFLAGS = -DUSE_COMMONCRYPTO -DUSE_LIBCOMPRESSION -DiOS10 -DDER_MULTIBYTE_TAGS=1 -D__unused="__attribute__((unused))" -DDER_TAG_SIZE=8 -I../XPF/external/img4lib -Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter
XPF_DEPS = $(filter-out ../XPF/external/img4lib/libvfs/vfs_lzvn.c, $(wildcard ../XPF/external/img4lib/lzss.c ../XPF/external/img4lib/libvfs/*.c ../XPF/external/img4lib/libDER/*.c))

CFLAGS = $(XPF_CFLAGS) $(CHOMA_CFLAGS) -framework Security -framework Foundation -framework CoreServices -framework IOKit -framework IOSurface -framework Security -framework IOMobileFramebuffer -framework LocalAuthentication -weak_framework CoreGraphics -weak_framework ImageIO -I../.include -I./src -I./src/ui-stub -I../../Application/Dopamine/Jailbreak -I../../Application/Dopamine/Extensions -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -Wno-availability -miphoneos-version-min=15.0 -fobjc-arc -I$(shell brew --prefix)/opt/libarchive/include -Iexternal/include -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -L../.build -larchive -lbsm -lcompression -lMobileGestalt -F ../_external/frameworks

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

# FIX: thêm ../_external/modules/litehook/src/*.c vào source list để linker
# tìm thấy symbol _litehook_rebind_symbol được roothide_hide.c gọi.
# RootHide port Build 3: compile the unsandbox namecache-publication sources
# into the app binary so publishFakeLibNoMount can call unsandbox() directly
# from the app process (never from launchd — a fault here must only ever
# crash the app, not pid 1).
$(TARGET): $(wildcard src/*.c src/*.m src/*.S src/ui-stub/*.m ../libjailbreak/src/*.c ../libjailbreak/src/*.m ../libjailbreak/src/*.S ../libjailbreak/src/roothider/unsandbox.m ../libjailbreak/src/roothider/unsandbox1.m ../libjailbreak/src/roothider/unsandbox2.m ../_external/modules/litehook/src/*.c ../ChOma/src/*.c ../XPF/src/*.c ../../Application/Dopamine/Jailbreak/*.m ../../Application/Dopamine/Jailbreak/*.c ../../Application/Dopamine/Extensions/NSData+Hex.m external/lib/*.a) $(XPF_DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)