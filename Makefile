CC=gcc
RELEASE=v0.04
CFLAGS=-Wall -ggdb -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(RELEASE)\"
LIBRARY_FLAGS=-lmhash

MANPAGE=duperemove.8

DIST_SOURCES=csum.c csum.h duperemove.c hash-tree.c hash-tree.h results-tree.c results-tree.h kernel.h LICENSE list.h Makefile rbtree.c rbtree.h rbtree.txt README TODO dedupe.c dedupe.h btrfs-ioctl.h filerec.c filerec.h $(MANPAGE)
DIST=duperemove-$(RELEASE)
DIST_TARBALL=$(DIST).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

objects = duperemove.o rbtree.o csum.o hash-tree.o results-tree.o dedupe.o filerec.o
progs = duperemove

all: $(progs) kernel.h list.h btrfs-ioctl.h

duperemove: $(objects) kernel.h duperemove.c
	$(CC) $(objects) $(LIBRARY_FLAGS) -o duperemove

tarball: clean
	mkdir -p $(TEMP_INSTALL_DIR)/$(DIST)
	cp $(DIST_SOURCES) $(TEMP_INSTALL_DIR)/$(DIST)
	tar -C $(TEMP_INSTALL_DIR) -zcf $(DIST_TARBALL) $(DIST)
	rm -fr $(TEMP_INSTALL_DIR)

btrfs-extent-same: btrfs-extent-same.c
	$(CC) -Wall -o btrfs-extent-same btrfs-extent-same.c

clean:
	rm -fr $(objects) $(progs) $(DIST_TARBALL) btrfs-extent-same *~
