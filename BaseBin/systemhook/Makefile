TARGET = systemhook.dylib
CC = clang

CFLAGS = -I../.include -I./src -I../_external/modules/litehook/src -I../_external/include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -install_name @loader_path/$(TARGET) -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -Os -moutline
# RootHide port Build 3.2: DO NOT link -ljailbreak here (Relaxin architecture).
#
# systemhook.dylib is published (kernel namecache) into /usr/lib as
# systemhook-<jbrand>.dylib, where it must be SELF-CONTAINED: its
# @loader_path is /usr/lib, and /usr/lib/libjailbreak.dylib does not exist
# (and must NEVER exist - a fixed jailbreak filename in /usr/lib is a
# trivial detection vector). Relaxin upstream links no libjailbreak either:
# every libjailbreak symbol systemhook needs is compiled directly into the
# binary (jbclient_*.c, inline_svc.[cS], hookd.c, roothider/jailbreakd.c,
# plus the local copies in src/common/ and src/roothider_common.c).
#
# Verified by static analysis (scripts/analyze_systemhook_deps2.py):
# 0 real external libjailbreak references remain. The old -ljailbreak flag
# was a leftover from stock Dopamine (where systemhook.dylib and
# libjailbreak.dylib sit next to each other in /basebin and @loader_path
# resolves); it only added a spurious LC_LOAD_DYLIB entry that made every
# /usr/lib-published systemhook load abort with
# "Library not loaded: @loader_path/libjailbreak.dylib".
LDFLAGS = -dynamiclib

sign: $(TARGET)
	@ldid -Cadhoc -S $^

# RootHide port: removed `../libjailbreak/src/roothide_hide.c` (patchwork file deleted).
# Added `../libjailbreak/src/roothider/jailbreakd.c` (Relaxin upstream RootHide jailbreakd client).
$(TARGET): $(wildcard src/*.[cSm] src/common/*.[cSm] ../libjailbreak/src/jbclient_*.c ../libjailbreak/src/inline_svc.[cS] ../libjailbreak/src/hookd.c ../libjailbreak/src/roothider/jailbreakd.c ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
