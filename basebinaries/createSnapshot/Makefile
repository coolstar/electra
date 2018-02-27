TARGET  = createSnapshot
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
# it is injected into trust cache by code
# which only supports sha-256 signatures
LDID    = ldid
CFLAGS  = -Wall

.PHONY: all clean

DEBUG ?= 0
ifeq ($(DEBUG), 1)
else
    CFLAGS += -O2
endif

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.c | $(OUTDIR)
	$(CC) -o $@ $^ $(CFLAGS)
	$(LDID) -SEnt.plist $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
