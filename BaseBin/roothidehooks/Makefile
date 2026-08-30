MIN_IOS_VERSION ?= 15.0

DEBUG ?= 0
SDK ?= iphoneos
ARCHS ?= arm64 arm64e
OUTPUT_DIR ?= $(abspath $(CURDIR)/../.build)
OBJECT_DIR := $(CURDIR)/.objects

BASEBIN_DIR := $(abspath $(CURDIR)/..)
# RootHide port: in Relaxin, VENDOR_DIR was $(CURDIR)/../../.. because the
# roothidehooks subproject lived at Vendor/Dopamine/BaseBin/roothidehooks/
# (3 levels up = Vendor/ where CaptainHook/ lives). In Kernel-JB, the
# roothidehooks subproject lives at BaseBin/roothidehooks/ and CaptainHook/
# lives at the repo root — so only 2 levels up.
VENDOR_DIR := $(abspath $(CURDIR)/../..)
OUTPUT := $(OUTPUT_DIR)/roothidehooks.dylib
# RootHide port: use simple 'wildcard *.m' (no $(CURDIR) prefix) so that
# the pattern rule below can match sources by stem. Prefixing with the
# absolute CURDIR path confused make's stem extraction on macOS GNU make,
# causing "No rule to make target .o" errors.
SOURCES := $(sort $(wildcard *.m))
OBJECTS := $(patsubst %.m,$(OBJECT_DIR)/%.o,$(SOURCES))
HEADERS := $(sort $(wildcard *.h)) \
	$(VENDOR_DIR)/CaptainHook/CaptainHook.h

# Kernel-JB adaptation: CaptainHook/ now lives at repo root (parallel to BaseBin/).
# VENDOR_DIR resolves to <repo_root>, so the include path stays <repo_root>/CaptainHook/CaptainHook.h.
LINK_INPUTS := \
	$(BASEBIN_DIR)/.build/libjailbreak.dylib \
	$(BASEBIN_DIR)/_external/lib/libellekit.tbd \
	$(BASEBIN_DIR)/_external/lib/libroothide.tbd

CC := xcrun --sdk $(SDK) clang
ARCH_FLAGS := $(foreach arch,$(ARCHS),-arch $(arch))
CPPFLAGS := \
	-I$(VENDOR_DIR) \
	-I$(BASEBIN_DIR)/.include \
	-I$(BASEBIN_DIR)/_external/include
CFLAGS := \
	$(ARCH_FLAGS) \
	-miphoneos-version-min=$(MIN_IOS_VERSION) \
	-fobjc-arc \
	-fblocks \
	-Werror \
	-DDEBUG=$(DEBUG)
LDFLAGS := \
	$(ARCH_FLAGS) \
	-miphoneos-version-min=$(MIN_IOS_VERSION) \
	-dynamiclib \
	-Wl,-S \
	-Wl,-x \
	-Wl,-install_name,/basebin/roothidehooks.dylib \
	-Wl,-rpath,@loader_path/.jbroot/Library/Frameworks \
	-Wl,-rpath,@loader_path/fallback \
	-L$(BASEBIN_DIR)/.build \
	-L$(BASEBIN_DIR)/_external/lib \
	-ljailbreak \
	-lellekit \
	-lroothide \
	-framework Foundation \
	-framework CoreFoundation \
	-framework Security

.DEFAULT_GOAL := all

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS) $(LINK_INPUTS)
	@mkdir -p $(OUTPUT_DIR)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
# RootHide port (CRITICAL, upstream parity): sign the dylib with ldid.
# Dopamine2-roothide runs `ldid -S roothidehooks.dylib` in its after-all
# hook. Without an adhoc code signature:
#   1. `trustcache create` cannot compute a cdhash -> roothidehooks.dylib
#      is silently LEFT OUT of basebin.tc.
#   2. The patched dyld's fcntl LV-bypass (dyldhook/src/lv_bypass.c) only
#      fires when dyld attaches a signature (F_ADDFILESIGS) - an unsigned
#      dylib never gets one, so it cannot be dynamically trusted either.
#   => dlopen("<jbroot>/basebin/roothidehooks.dylib") returns NULL
#   => ASSERT(roothidehooks != NULL) in systemhook/src/roothider_main.c:68
#   => EVERY root jailbreak binary spawned after publish dies with exit 6
#      (killall, /bin/sh prep_bootstrap.sh, dpkg -i, ...)
#   => bootstrap finalization completely broken.
# Verified against CI artifact of build cf1e9ff: this was the ONLY
# unsigned Mach-O in basebin.tar.
	@ldid -Cadhoc -S $@

# RootHide port: pattern rule uses bare '%.m' (not '$(CURDIR)/%.m') so make's
# stem extraction works correctly. The OBJECTS list also uses bare '%.m' so
# they stay consistent.
$(OBJECT_DIR)/%.o: %.m $(HEADERS)
	@mkdir -p $(OBJECT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJECT_DIR)/lsd.o: CFLAGS += -fno-objc-arc

clean:
	rm -f $(OUTPUT)
	rm -rf $(OBJECT_DIR)

.PHONY: all clean
