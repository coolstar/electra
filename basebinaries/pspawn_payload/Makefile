TARGET  = pspawn_payload.dylib
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
# it is injected into trust cache by code
# which only supports sha-256 signatures
LDID    = ldid2
CFLAGS  = -Wall

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DPSPAWN_PAYLOAD_DEBUG
else
    CFLAGS += -O2
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): pspawn_payload.m fishhook.c common.c | $(OUTDIR)
	$(CC) -dynamiclib -o $@ $^ -framework Foundation $(CFLAGS)
	$(LDID) -S $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
