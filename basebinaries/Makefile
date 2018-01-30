TARGET  = basebinaries.tar
OUTDIR ?= bin

.PHONY: all clean

SUBPRJ = amfid_payload inject_criticald jailbreakd jailbreakd_client pspawn_payload libjailbreak_xpc
all: $(OUTDIR)/$(TARGET)

MFLAGS = OUTDIR=$(abspath $(OUTDIR))

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    MFLAGS += DEBUG=1
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(addprefix $(OUTDIR)/, $(SUBPRJ)) | $(OUTDIR)
	#tar -cvf $@ $^
	rm -f $@
	cd $(OUTDIR); gtar -pcvf $(abspath $@) $(notdir bin/*)

$(OUTDIR)/%: | $(OUTDIR)
	$(MAKE) -C $(notdir $@) $(MFLAGS)

clean:
	rm -rf $(OUTDIR)
