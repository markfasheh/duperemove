CC=gcc
RELEASE=v0.07
CFLAGS=-Wall -ggdb -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(RELEASE)\"

MANPAGES=duperemove.8 btrfs-extent-same.8

DIST_SOURCES=csum-gcrypt.c csum-mhash.c csum.h duperemove.c hash-tree.c hash-tree.h results-tree.c results-tree.h kernel.h LICENSE list.h Makefile rbtree.c rbtree.h rbtree.txt README TODO dedupe.c dedupe.h btrfs-ioctl.h filerec.c filerec.h $(MANPAGES) btrfs-extent-same.c debug.h util.c util.h
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

CFLAGS += $(crypt_CFLAGS)
LIBRARY_FLAGS += $(crypt_LIBS)

objects = duperemove.o rbtree.o hash-tree.o results-tree.o dedupe.o filerec.o util.o $(hash_obj)
progs = duperemove

all: $(progs) kernel.h list.h btrfs-ioctl.h debug.h

duperemove: $(objects) kernel.h duperemove.c
	$(CC) $(objects) $(LIBRARY_FLAGS) -o duperemove

tarball: clean
	mkdir -p $(TEMP_INSTALL_DIR)/$(DIST)
	cp $(DIST_SOURCES) $(TEMP_INSTALL_DIR)/$(DIST)
	tar -C $(TEMP_INSTALL_DIR) -zcf $(DIST_TARBALL) $(DIST)
	rm -fr $(TEMP_INSTALL_DIR)

btrfs-extent-same: btrfs-extent-same.c
	$(CC) -Wall -o btrfs-extent-same btrfs-extent-same.c

csum-test: $(hash_obj) csum-test.c
	$(CC) -Wall $(hash_obj) $(CFLAGS) $(LIBRARY_FLAGS) -o csum-test csum-test.c

filerec-test: filerec.c filerec.h
	$(CC) -Wall $(CFLAGS) $(LIBRARY_FLAGS) -DFILEREC_TEST filerec.c -o filerec-test

clean:
	rm -fr $(objects) $(progs) $(DIST_TARBALL) btrfs-extent-same filerec-test csum-*.o *~
