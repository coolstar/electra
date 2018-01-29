TARGET = libjailbreak
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
LDID 	= ldid

.PHONY: all clean

CFLAGS += -O2

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
		mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
		$(CC) -o $@ $^ -framework Foundation
		$(LDID) -S $@

clean:
		rm -f $(OUTDIR)/$(TARGET)
