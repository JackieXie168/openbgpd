CURDIR = .

PROG=	bgpctl
SRCS=	bgpctl.c parser.c ../bgpd/util.c ../bgpd/timer.c
SRCS+=	irrfilter.c whois.c irr_asset.c irr_prefix.c irr_output.c
SRCS+=	irr_parser.c
SRCS+=	../openbsd-compat/fmt_scaled.c ../openbsd-compat/imsg.c ../openbsd-compat/imsg-buffer.c
CFLAGS+= -Wall -Werror
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I$(CURDIR) -I$(CURDIR)/../bgpd -I$(CURDIR)/../openbsd-compat
MAN=	bgpctl.8
LDFLAGS= -lbsd -lrt

CC = gcc

OBJS = $(subst .c,.o,$(subst .y,.o,$(SRCS)))

$(PROG): $(OBJS)

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(PROG)

.PHONY: distclean clean
