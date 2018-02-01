TARGET = libjailbreak
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
LDID 	= ldid
CFLAGS  = -Wall -dynamiclib

.PHONY: all clean

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -DLIBJAILBREAK_DEBUG
else
	CFLAGS += -O2
endif

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
		mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
		$(CC) -o $@ $^ -framework Foundation $(CFLAGS)
		$(LDID) -S $@

clean:
		rm -f $(OUTDIR)/$(TARGET)
