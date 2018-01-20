TARGET  = inject_criticald
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
# it is injected into trust cache by code
# which only supports sha-256 signatures
LDID    = ldid2
CFLAGS  = -Wall

.PHONY: all clean

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DINJECT_CRITICALD_DEBUG
else
    CFLAGS += -O2
endif

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
	$(CC) -o $@ $^ -framework Foundation -framework IOKit $(CFLAGS)
	$(LDID) -SEnt.plist $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
