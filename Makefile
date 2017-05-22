SUBDIRS = passes static test

all:
	@for dir in $(SUBDIRS); do \
		make -C $$dir; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		make -C $$dir clean; \
	done

.PHONY: all clean
