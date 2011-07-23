#	$OpenBSD: Makefile,v 1.10 2007/12/20 17:08:48 henning Exp $

.PATH:		${.CURDIR}/../bgpd ${.CURDIR}/../openbsd-compat

PROG=	bgpctl
SRCS=	bgpctl.c parser.c util.c timer.c
SRCS+=	irrfilter.c whois.c irr_asset.c irr_prefix.c irr_output.c
SRCS+=	irr_parser.c
SRCS+=	fmt_scaled.c imsg.c imsg-buffer.c
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../bgpd -I${.CURDIR}/../openbsd-compat
MAN=	bgpctl.8
LDADD= -lutil
DPADD+= ${LIBUTIL}

.include <bsd.prog.mk>
