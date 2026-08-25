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
