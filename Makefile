CC          = gcc
CFLAGS     ?= -O2 -pipe -Wall -Wextra -pedantic
CFLAGS     += -std=c99
STRIP       = strip
INSTALL     = install
UNAME       = uname
LUA         = lua

OS          = $(shell $(UNAME))
LUA_INCDIR  =
LUA_PATH    = $(shell $(LUA) -e 'print(package.path:match("(/[^;]*)/%?"))')
LUA_CPATH   = $(shell $(LUA) -e 'print(package.cpath:match("(/[^;]*)/%?"))')

ifeq ($(OS),Darwin)
SHARED      = -dynamiclib -Wl,-undefined,dynamic_lookup
STRIP_ARGS  = -x
else
SHARED      = -shared
endif

clibs = sha1

ifdef NDEBUG
CFLAGS     += -DNDEBUG
endif

ifdef V
E=@\#
Q=
else
E=@echo
Q=@
endif

.PHONY: all strip install clean
.PRECIOUS: %.o

all: $(clibs:%=%.so)

%.o: %.c
	$E '  CC $@'
	$Q$(CC) $(CFLAGS) $(LUA_INCDIR:%=-I%) -fPIC -nostartfiles -c $< -o $@

%.so: %.o
	$E '  LD $@'
	$Q$(CC) $(SHARED) $^ -o $@ $(LDFLAGS)

cpath-install:
	$E "  INSTALL -d $(LUA_CPATH)"
	$Q$(INSTALL) -d $(DESTDIR)$(LUA_CPATH)

%.so-install: %.so cpath-install
	$E "  INSTALL $<"
	$Q$(INSTALL) $< $(DESTDIR)$(LUA_CPATH)/$<

install: $(clibs:%=%.so-install)

%-strip: %
	$E '  STRIP $<'
	$Q$(STRIP) $(STRIP_ARGS) $<

strip: $(clibs:%=%.so-strip)

clean:
	rm -f $(clibs:%=%.so) *.o *.c~ *.h~
