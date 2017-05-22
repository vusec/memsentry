PROTMETHOD ?= sfi
RW         ?= rw

include ../config.mk

CFLAGS  := -Wall -g -O3 -emit-llvm -c -I../include
OPTFLAGS := -load ../passes/obj/libmemsentry-pass.so -memsentry \
            -memsentry-rw=$(RW) -memsentry-prot-method=$(PROTMETHOD) \
			-memsentry-verify-external-call-args=false \
			-memsentry-whitelist-section=safe_functions -O3
#OPTFLAGS := -load ../passes/obj/libmemsentry-pass.so \
	-memsentry-benchdomain-points=call-ret \
	-memsentry-benchdomain \
	-memsentry-prot-method=vmfunc \
	-memsentry \
	-memsentry-benchdomain-post
LDFLAGS := -g -O3
OBJDIR  ?= ./obj

PROGS := simple
PROGS := $(patsubst %,$(OBJDIR)/%,$(PROGS))

STATICFILES := $(wildcard ../static/obj/*.o)

.PHONY: all clean

all: $(PROGS)

$(OBJDIR)/%: $(OBJDIR)/%-opt.bc
	$(CLANG) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%-opt.bc: $(OBJDIR)/%-link.bc
	$(OPT) $(OPTFLAGS) < $< > $@

$(OBJDIR)/%-link.bc: $(OBJDIR)/%.bc $(STATICFILES)
	$(LLINK) $^ > $@

$(OBJDIR)/%.bc: %.c | $(OBJDIR)
	$(CLANG) $(CFLAGS) -o $@ $<

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)
