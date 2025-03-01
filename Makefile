VERSION ?= $(shell git describe --abbrev=4 --dirty --always --tags;)
IS_RELEASE ?= $(if $(filter $(shell git rev-list $(shell git describe --abbrev=0 --tags --exclude '*dev';)..HEAD --count;),0),1,0)

CC ?= gcc
CFLAGS ?= -Wall -ggdb -std=gnu11 -Werror=strict-prototypes -MMD
PKG_CONFIG ?= pkg-config

MANPAGES=duperemove.8 btrfs-extent-same.8 hashstats.8 show-shared-extents.8
ZSH_COMPLETION=completion/zsh/_duperemove

# tests.c is ulgy: it includes lots of c files, to get access to inlined code
CFILES = $(filter-out tests.c,$(wildcard *.c))
DEPENDS := $(CFILES:.c=.d)
OBJECTS := $(CFILES:.c=.o)
install_progs = duperemove hashstats btrfs-extent-same
progs = $(install_progs) csum-test
PROGS_OBJECTS := $(addsuffix .o,$(basename $(progs)))
SHARED_OBJECTS := $(filter-out $(PROGS_OBJECTS),$(OBJECTS))

DIST_SOURCES:=$(CFILES) $(wildcard *.h) LICENSE Makefile \
	rbtree.txt README.md $(MANPAGES) SubmittingPatches docs/duperemove.html
DIST=duperemove-$(VERSION)
DIST_TARBALL=$(VERSION).tar.gz
TEMP_INSTALL_DIR:=$(shell mktemp -du -p .)

EXTRA_CFLAGS=$(shell $(PKG_CONFIG) --cflags glib-2.0,sqlite3,blkid,mount,uuid,libbsd)
EXTRA_LIBS=$(shell $(PKG_CONFIG) --libs glib-2.0,sqlite3,blkid,mount,uuid)

ifdef DEBUG
	DEBUG_FLAGS = -ggdb3 -fsanitize=address -fno-omit-frame-pointer	-O0 \
			-DDEBUG_BUILD -DSQLITE_DEBUG -DSQLITE_MEMDEBUG \
			-DSQLITE_ENABLE_EXPLAIN_COMMENTS -fsanitize-address-use-after-scope
else
	CFLAGS += -O2
endif

override CFLAGS += -D_FILE_OFFSET_BITS=64 -DVERSTRING=\"$(VERSION)\" \
	$(EXTRA_CFLAGS) $(DEBUG_FLAGS) \
	-DIS_RELEASE=$(IS_RELEASE) -D_GNU_SOURCE
LIBRARY_FLAGS += -Wl,--as-needed -latomic -lm $(EXTRA_LIBS)

# make C=1 to enable sparse
ifdef C
	CC = sparse -D__CHECKER__ -D__CHECK_ENDIAN__ -Wbitwise \
		-Wuninitialized -Wshadow -Wundef
endif

DESTDIR ?= /
PREFIX ?= /usr/local
SHAREDIR = $(PREFIX)/share
BINDIR = $(PREFIX)/bin
MANDIR = $(SHAREDIR)/man

all: $(progs)
debug:
	@echo "Deprecated, use \"make DEBUG=1\" instead please."

$(MANPAGES): %.8: markdown/%.md
	pandoc --standalone markdown/$(subst .8,,$@).md --to man -o $(subst .8,,$@).8
	pandoc --standalone markdown/$(subst .8,,$@).md --to html -o docs/$(subst .8,,$@).html

-include $(DEPENDS)
$(progs): $(OBJECTS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(SHARED_OBJECTS) $@.o -o $@ $(LIBRARY_FLAGS)

.PHONY: test
test:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) tests.c -o $@ $(LIBRARY_FLAGS)
	./test

install: $(install_progs) $(MANPAGES) $(ZSH_COMPLETION)
	mkdir -p -m 0755 $(DESTDIR)$(BINDIR)
	for prog in $(install_progs); do \
		install -m 0755 $$prog $(DESTDIR)$(BINDIR); \
	done
	mkdir -p -m 0755 $(DESTDIR)$(MANDIR)/man8
	for man in $(MANPAGES); do \
		install -m 0644 $$man $(DESTDIR)$(MANDIR)/man8; \
	done
	mkdir -p -m 0755 $(DESTDIR)$(SHAREDIR)/zsh/site-functions
	for completion in $(ZSH_COMPLETION); do \
		install -m 0644 $$completion $(DESTDIR)$(SHAREDIR)/zsh/site-functions; \
	done

uninstall:
	for prog in $(install_progs); do \
		rm -f $(DESTDIR)$(BINDIR)/$$prog; \
	done
	for man in $(MANPAGES); do \
		rm -f $(DESTDIR)$(MANDIR)/man8/$$man; \
	done
	for completion in $(ZSH_COMPLETION); do \
		rm -f $(DESTDIR)$(SHAREDIR)/zsh/site-functions/$${completion##*/}; \
	done

tarball: clean $(DIST_SOURCES)
	mkdir -p $(TEMP_INSTALL_DIR)/$(DIST)
	cp $(DIST_SOURCES) $(TEMP_INSTALL_DIR)/$(DIST)
	tar -C $(TEMP_INSTALL_DIR) -zcf $(DIST_TARBALL) $(DIST)
	rm -fr $(TEMP_INSTALL_DIR)

clean:
	rm -fr $(OBJECTS) $(progs) $(DIST_TARBALL) $(DEPENDS) *~

doc: $(MANPAGES)
