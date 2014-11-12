RELEASE=v0.09.beta2

CC = gcc
CFLAGS = -Wall -ggdb -O3

MANPAGES=duperemove.8 btrfs-extent-same.8

DIST_SOURCES=csum-gcrypt.c csum-mhash.c csum.h duperemove.c hash-tree.c hash-tree.h results-tree.c results-tree.h kernel.h LICENSE list.h Makefile rbtree.c rbtree.h rbtree.txt README TODO dedupe.c dedupe.h btrfs-ioctl.h filerec.c filerec.h btrfs-util.c btrfs-util.h $(MANPAGES) btrfs-extent-same.c debug.h util.c util.h serialize.c serialize.h hashstats.c
DIST=duperemove-$(RELEASE)
DIST_TARBALL=$(DIST).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

hash_obj=csum-gcrypt.o
crypt_CFLAGS=$(shell libgcrypt-config --cflags)
crypt_LIBS=$(shell libgcrypt-config --libs)
ifdef USE_MHASH
	hash_obj=csum-mhash.o
	crypt_CFLAGS=
	crypt_LIBS=-lmhash
endif

ifdef USE_MURMUR3
	hash_obj=csum-murmur3.o
	crypt_CFLAGS=
	crypt_LIBS=
endif

glib_CFLAGS=$(shell pkg-config --cflags glib-2.0)
glib_LIBS=$(shell pkg-config --libs glib-2.0)

override CFLAGS += -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(RELEASE)\" \
	$(crypt_CFLAGS) $(glib_CFLAGS)
LIBRARY_FLAGS += $(crypt_LIBS) $(glib_LIBS)

objects = duperemove.o rbtree.o hash-tree.o results-tree.o dedupe.o filerec.o util.o serialize.o btrfs-util.o $(hash_obj)
progs = duperemove

DESTDIR = /
PREFIX = /usr/local
SHAREDIR = $(PREFIX)/share
SBINDIR = $(PREFIX)/sbin
MANDIR = $(SHAREDIR)/man

all: $(progs) kernel.h list.h btrfs-ioctl.h debug.h

duperemove: $(objects) kernel.h duperemove.c
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

csum-test: $(hash_obj) csum-test.c
	$(CC) $(CFLAGS) $(hash_obj) -o csum-test csum-test.c  $(LIBRARY_FLAGS)

filerec-test: filerec.c filerec.h rbtree.o
	$(CC) $(CFLAGS) -DFILEREC_TEST filerec.c rbtree.o -o filerec-test $(LIBRARY_FLAGS)

hashstats_obj = $(hash_obj) rbtree.o hash-tree.o filerec.o util.o serialize.o results-tree.o
hashstats: $(hashstats_obj) hashstats.c
	$(CC) $(CFLAGS) $(hashstats_obj) hashstats.c -o hashstats $(LIBRARY_FLAGS)

clean:
	rm -fr $(objects) $(progs) $(DIST_TARBALL) btrfs-extent-same filerec-test hashstats csum-*.o *~
