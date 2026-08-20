TARGET = libroot.dylib
CC = clang

CFLAGS = -I../../BaseBin/.include -Isrc -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -O2
LDFLAGS = -dynamiclib -rpath @loader_path/../lib

all: $(TARGET) sign

sign: $(TARGET)
        @ldid -Cadhoc -S $^

$(TARGET): $(wildcard src/*.c ../../BaseBin/libjailbreak/src/jbclient_*.c)
        $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
        @rm -f $(TARGET)
        @rm -f libroot.deb

# RootHide Bootstrap does NOT use /var/jb. All package paths must be RELATIVE
# to the jbroot (the bootstrap is extracted at jbroot, so `./usr/lib/foo`
# in the deb becomes `<jbroot>/usr/lib/foo` on disk). The previous path
# `/var/jb/usr/lib/...` caused `dpkg -i libroot.deb` to fail with exit code 2
# because `/var/jb` no longer exists after the RootHide patches removed it.
package: all
        @mkdir -p .package/DEBIAN
        @mkdir -p .package/usr/lib
        @cp control .package/DEBIAN/control
        @cp libroot.dylib .package/usr/lib/libroot.dylib
        @dpkg-deb --root-owner-group -Zzstd -b .package ./libroot.deb
        @rm -rf .package
