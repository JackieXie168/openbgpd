CURDIR = .

CONFFILE = /etc/bgpd.conf

PROG=	bgpd
SRCS=	bgpd.c session.c log.c parse.y config.c \
	rde.c rde_rib.c rde_decide.c rde_prefix.c mrt.c kroute.c \
	control.c ../openbsd-compat/pfkey_compat.c rde_update.c rde_attr.c printconf.c \
	rde_filter.c pftable.c name2id.c util.c carp.c timer.c \
	../openbsd-compat/imsg.c ../openbsd-compat/imsg-buffer.c
CFLAGS+= -Wall -Werror -I$(CURDIR)
CFLAGS+= -I$(CURDIR)/../openbsd-compat
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -DCONFFILE=\"${CONFFILE}\"

CFLAGS+= -DIPV6_LINKLOCAL_PEER

YFLAGS=

LDFLAGS = -lbsd -lrt

MAN= bgpd.8 bgpd.conf.5

CC = gcc

OBJS = $(subst .c,.o,$(subst .y,.o,$(SRCS)))

$(PROG): $(OBJS)

clean:
	rm -f $(OBJS)
	rm -f $(subst .y,.c,$(filter %.y,$(SRCS)))

distclean: clean
	rm -f $(PROG)

.PHONY: distclean clean
