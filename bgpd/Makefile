#	$OpenBSD: Makefile,v 1.29 2010/05/26 16:44:32 nicm Exp $

.PATH:		${.CURDIR}/.. ${.CURDIR}/../openbsd-compat

CONFFILE?=	${PREFIX}/etc/bgpd.conf

PROG=	bgpd
SRCS=	bgpd.c session.c log.c parse.y config.c \
	rde.c rde_rib.c rde_decide.c rde_prefix.c mrt.c kroute.c \
	control.c pfkey_compat.c rde_update.c rde_attr.c printconf.c \
	rde_filter.c pftable.c name2id.c util.c carp.c timer.c \
	imsg.c imsg-buffer.c
CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/../openbsd-compat
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -DCONFFILE=\"${CONFFILE}\"
.if defined(IPV6_LINKLOCAL_PEER)
CFLAGS+= -DIPV6_LINKLOCAL_PEER
.endif
YFLAGS=
MAN= bgpd.8 bgpd.conf.5

.include <bsd.prog.mk>
