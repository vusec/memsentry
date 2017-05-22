include ../config.mk

CC     := $(CLANG)
CFLAGS := -c -emit-llvm -fpic -Wall -Wextra -O2 -I ../include
OBJDIR ?= ./obj

OBJS := helpers init mpx_init crypt alloc
OBJS := $(patsubst %,$(OBJDIR)/%.o,$(OBJS))

LIB := libmemsentry-rt.a


.PHONY: all clean

all: $(OBJDIR)/$(LIB)

$(OBJDIR)/$(LIB): $(OBJS)
	ar rcs $@ $^

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)
