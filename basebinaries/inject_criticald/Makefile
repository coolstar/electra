TARGET  = inject_criticald
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64
LDID    = ldid

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
	$(CC) -o $@ $^ -framework Foundation -framework IOKit $(CFLAGS)
	$(LDID) -SEnt.plist $@

clean:
	rm -f $(TARGET)
