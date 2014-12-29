RELEASE=v0.10-dev

CC = gcc
CFLAGS = -Wall -ggdb

MANPAGES=duperemove.8 btrfs-extent-same.8 hashstats.8 show-shared-extents.8

HEADERS=csum.h hash-tree.h results-tree.h kernel.h list.h rbtree.h dedupe.h \
	btrfs-ioctl.h filerec.h btrfs-util.h debug.h util.h serialize.h \
	memstats.h file_scan.h find_dupes.h run_dedupe.h xxhash.h \
	sha256.h sha256-config.h bswap.h
CFILES=duperemove.c hash-tree.c results-tree.c rbtree.c dedupe.c filerec.c \
	btrfs-util.c util.c serialize.c memstats.c file_scan.c find_dupes.c \
	run_dedupe.c csum.c
hash_CFILES=csum-xxhash.c xxhash.c csum-murmur3.c csum-sha256.c sha256.c

CFILES += $(hash_CFILES)

hashstats_CFILES=hashstats.c
btrfs_extent_same_CFILES=btrfs-extent-same.c
csum_test_CFILES=csum-test.c

DIST_CFILES:=$(CFILES) $(hashstats_CFILES) $(btrfs_extent_same_CFILES) \
	$(csum_test_CFILES)
DIST_SOURCES:=$(DIST_CFILES) $(HEADERS) LICENSE LICENSE.xxhash Makefile \
	rbtree.txt README.md $(MANPAGES) SubmittingPatches FAQ.md
DIST=duperemove-$(RELEASE)
DIST_TARBALL=$(DIST).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

objects = $(CFILES:.c=.o)

hash_obj=$(hash_CFILES:.c=.o)
hashstats_obj = $(hash_obj) rbtree.o hash-tree.o filerec.o util.o serialize.o \
	 results-tree.o csum.o
show_shared_obj = rbtree.o util.o
csum_test_obj = $(hash_obj) util.o csum.o

progs = duperemove hashstats btrfs-extent-same show-shared-extents csum-test

glib_CFLAGS=$(shell pkg-config --cflags glib-2.0)
glib_LIBS=$(shell pkg-config --libs glib-2.0)

override CFLAGS += -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(RELEASE)\" \
	$(hash_CFLAGS) $(glib_CFLAGS) -rdynamic
LIBRARY_FLAGS += $(hash_LIBS) $(glib_LIBS)

# make C=1 to enable sparse
ifdef C
	check = sparse -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise \
		-Wuninitialized -Wshadow -Wundef
else
	check = true
endif

DESTDIR = /
PREFIX = /usr/local
SHAREDIR = $(PREFIX)/share
SBINDIR = $(PREFIX)/sbin
MANDIR = $(SHAREDIR)/man

.c.o:
	$(check) $(CFLAGS) -c $< -o $@ $(LIBRARY_FLAGS)
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBRARY_FLAGS)

all: $(progs)
#TODO: Replace this with an auto-dependency
$(objects): $(HEADERS)
duperemove: $(objects)
	$(CC) $(CFLAGS) $(objects) -o duperemove $(LIBRARY_FLAGS)

tarball: clean
	mkdir -p $(TEMP_INSTALL_DIR)/$(DIST)
	cp $(DIST_SOURCES) $(TEMP_INSTALL_DIR)/$(DIST)
	tar -C $(TEMP_INSTALL_DIR) -zcf $(DIST_TARBALL) $(DIST)
	rm -fr $(TEMP_INSTALL_DIR)

btrfs-extent-same: btrfs-extent-same.c
	$(CC) $(CFLAGS) -o btrfs-extent-same btrfs-extent-same.c

install: $(progs) $(MANPAGES)
	mkdir -p -m 0755 $(DESTDIR)$(SBINDIR)
	for prog in $(progs); do \
		install -m 0755 $$prog $(DESTDIR)$(SBINDIR); \
	done
	mkdir -p -m 0755 $(DESTDIR)$(MANDIR)/man8
	for man in $(MANPAGES); do \
		install -m 0644 $$man $(DESTDIR)$(MANDIR)/man8; \
	done

csum-test: $(csum_test_obj) csum-test.c
	$(CC) $(CFLAGS) $(csum_test_obj) -o csum-test csum-test.c  $(LIBRARY_FLAGS)

show-shared-extents: $(show_shared_obj) filerec.c
	$(CC) $(CFLAGS) -DFILEREC_TEST filerec.c $(show_shared_obj) -o show-shared-extents $(LIBRARY_FLAGS)

hashstats: $(hashstats_obj) hashstats.c
	$(CC) $(CFLAGS) $(hashstats_obj) hashstats.c -o hashstats $(LIBRARY_FLAGS)

clean:
	rm -fr $(objects) $(progs) $(DIST_TARBALL) btrfs-extent-same filerec-test show-shared-extents hashstats csum-*.o *~
