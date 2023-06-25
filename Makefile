VERSION=$(shell git describe --abbrev=4 --dirty --always --tags;)
ifeq ($(shell git rev-list $(shell git describe --abbrev=0 --tags --exclude '*dev';)..HEAD --count;), 0)
	IS_RELEASE=1
else
	IS_RELEASE=0
endif

CC ?= gcc
CFLAGS ?= -Wall -ggdb

MANPAGES=duperemove.8 btrfs-extent-same.8 hashstats.8 show-shared-extents.8

HEADERS=csum.h hash-tree.h results-tree.h kernel.h list.h rbtree.h dedupe.h \
	ioctl.h filerec.h btrfs-util.h debug.h util.h \
	memstats.h file_scan.h find_dupes.h run_dedupe.h xxhash.h \
	dbfile.h interval_tree.h interval_tree_generic.h \
	rbtree_augmented.h list_sort.h stats.h
CFILES=duperemove.c hash-tree.c results-tree.c rbtree.c dedupe.c filerec.c \
	btrfs-util.c util.c memstats.c file_scan.c find_dupes.c run_dedupe.c \
	csum.c dbfile.c interval_tree.c list_sort.c stats.c debug.c \
	csum-xxhash.c

hashstats_CFILES=hashstats.c
btrfs_extent_same_CFILES=btrfs-extent-same.c
csum_test_CFILES=csum-test.c

DIST_CFILES:=$(CFILES) $(hashstats_CFILES) $(btrfs_extent_same_CFILES) \
	$(csum_test_CFILES)
DIST_SOURCES:=$(DIST_CFILES) $(HEADERS) LICENSE LICENSE.xxhash Makefile \
	rbtree.txt README.md $(MANPAGES) SubmittingPatches docs/duperemove.html
DIST=duperemove-$(VERSION)
DIST_TARBALL=$(VERSION).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

objects = $(CFILES:.c=.o)

hashstats_obj = csum-xxhash.o rbtree.o hash-tree.o filerec.o util.o \
	results-tree.o csum.o dbfile.o interval_tree.o list_sort.o debug.o
show_shared_obj = rbtree.o util.o debug.o
csum_test_obj = csum-xxhash.o util.o csum.o debug.o

install_progs = duperemove hashstats btrfs-extent-same show-shared-extents
progs = $(install_progs) csum-test

glib_CFLAGS=$(shell pkg-config --cflags glib-2.0)
glib_LIBS=$(shell pkg-config --libs glib-2.0)
sqlite_CFLAGS=$(shell pkg-config --cflags sqlite3)
sqlite_LIBS=$(shell pkg-config --libs sqlite3)

ifdef DEBUG
	DEBUG_FLAGS = -ggdb3 -fsanitize=address -fno-omit-frame-pointer	-O0 \
			-DDEBUG_BUILD -DSQLITE_DEBUG -DSQLITE_MEMDEBUG \
			-DSQLITE_ENABLE_EXPLAIN_COMMENTS -fsanitize-address-use-after-scope
else
	CFLAGS += -O2
endif

override CFLAGS += -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(VERSION)\" \
	$(glib_CFLAGS) $(sqlite_CFLAGS) -rdynamic $(DEBUG_FLAGS) \
	-DIS_RELEASE=$(IS_RELEASE)
LIBRARY_FLAGS += -Wl,--as-needed -latomic -lm
LIBRARY_FLAGS += $(glib_LIBS) $(sqlite_LIBS)

# make C=1 to enable sparse
ifdef C
	check = sparse -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise \
		-Wuninitialized -Wshadow -Wundef
else
	check = @true
endif

DESTDIR ?= /
PREFIX ?= /usr/local
SHAREDIR = $(PREFIX)/share
BINDIR = $(PREFIX)/bin
MANDIR = $(SHAREDIR)/man

%.c.i: FORCE
	$(check) $(CPPFLAGS) $(CFLAGS) -c $(subst .i,,$@) -o $@ $(LIBRARY_FLAGS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -E $(subst .i,,$@) -o $@ $(LIBRARY_FLAGS)

%.c.o: FORCE
	$(check) $(CPPFLAGS) $(CFLAGS) -c $(subst .o,,$@) -o $@ $(LIBRARY_FLAGS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -c  $(subst .o,,$@) -o $@ $(LIBRARY_FLAGS)

all: $(progs)
debug:
	@echo "Deprecated, use \"make DEBUG=1\" instead please."

#TODO: Replace this with an auto-dependency
$(objects): $(HEADERS)
duperemove: $(objects)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(objects) -o duperemove $(LIBRARY_FLAGS)

tarball: clean
	mkdir -p $(TEMP_INSTALL_DIR)/$(DIST)
	cp $(DIST_SOURCES) $(TEMP_INSTALL_DIR)/$(DIST)
	tar -C $(TEMP_INSTALL_DIR) -zcf $(DIST_TARBALL) $(DIST)
	rm -fr $(TEMP_INSTALL_DIR)

btrfs-extent-same: btrfs-extent-same.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o btrfs-extent-same btrfs-extent-same.c

install: $(install_progs) $(MANPAGES)
	mkdir -p -m 0755 $(DESTDIR)$(BINDIR)
	for prog in $(install_progs); do \
		install -m 0755 $$prog $(DESTDIR)$(BINDIR); \
	done
	mkdir -p -m 0755 $(DESTDIR)$(MANDIR)/man8
	for man in $(MANPAGES); do \
		install -m 0644 $$man $(DESTDIR)$(MANDIR)/man8; \
	done

uninstall:
	for prog in $(install_progs); do \
		rm -f $(DESTDIR)$(BINDIR)/$$prog; \
	done
	for man in $(MANPAGES); do \
		rm -f $(DESTDIR)$(MANDIR)/man8/$$man; \
	done

csum-test: $(csum_test_obj) csum-test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(csum_test_obj) -o csum-test csum-test.c  $(LIBRARY_FLAGS)

show-shared-extents: $(show_shared_obj) filerec.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -DFILEREC_TEST filerec.c $(show_shared_obj) -o show-shared-extents $(LIBRARY_FLAGS)

hashstats: $(hashstats_obj) hashstats.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(hashstats_obj) hashstats.c -o hashstats $(LIBRARY_FLAGS)

clean:
	rm -fr $(objects) $(progs) $(DIST_TARBALL) btrfs-extent-same filerec-test show-shared-extents hashstats csum-*.o *~

FORCE:
