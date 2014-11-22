RELEASE=v0.09.beta3

CC = gcc
CFLAGS = -Wall -ggdb

MANPAGES=duperemove.8 btrfs-extent-same.8

CFILES=duperemove.c hash-tree.c results-tree.c rbtree.c dedupe.c filerec.c \
	btrfs-util.c util.c serialize.c memstats.c
hash_impl_CFILES=csum-mhash.c csum-gcrypt.c
hashstats_CFILES=hashstats.c
btrfs_extent_same_CFILES=btrfs-extent-same.c
csum_test_CFILES=csum-test.c
DIST_CFILES:=$(CFILES) $(hashstats_CFILES) $(btrfs_extent_same_CFILES) \
	$(csum_test_CFILES) $(hash_impl_CFILES)
HEADERS=csum.h hash-tree.h results-tree.h kernel.h list.h rbtree.h dedupe.h \
	btrfs-ioctl.h filerec.h btrfs-util.h debug.h util.h serialize.h \
	memstats.h
DIST_SOURCES:=$(DIST_CFILES) $(HEADERS) LICENSE Makefile rbtree.txt README.md \
	TODO $(MANPAGES) SubmittingPatches FAQ.md
DIST=duperemove-$(RELEASE)
DIST_TARBALL=$(DIST).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

crypt_CFILES=csum-gcrypt.c
crypt_CFLAGS=$(shell libgcrypt-config --cflags)
crypt_LIBS=$(shell libgcrypt-config --libs)
ifdef USE_MHASH
	crypt_CFILES=csum-mhash.c
	crypt_CFLAGS=
	crypt_LIBS=-lmhash
endif
crypt_obj=$(crypt_CFILES:.c=.o)

CFILES += $(crypt_CFILES)
objects = $(CFILES:.c=.o)

hashstats_obj = $(crypt_obj) rbtree.o hash-tree.o filerec.o util.o serialize.o \
	 results-tree.o
show_shared_obj = rbtree.o util.o
csum_test_obj = $(crypt_obj) util.o

progs = duperemove hashstats btrfs-extent-same show-shared-extents csum-test

glib_CFLAGS=$(shell pkg-config --cflags glib-2.0)
glib_LIBS=$(shell pkg-config --libs glib-2.0)

override CFLAGS += -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(RELEASE)\" \
	$(crypt_CFLAGS) $(glib_CFLAGS) -rdynamic
LIBRARY_FLAGS += $(crypt_LIBS) $(glib_LIBS)

DESTDIR = /
PREFIX = /usr/local
SHAREDIR = $(PREFIX)/share
SBINDIR = $(PREFIX)/sbin
MANDIR = $(SHAREDIR)/man

.c.o:
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
