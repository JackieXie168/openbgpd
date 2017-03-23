AM_CFLAGS = -I. -I.. -I$(top_srcdir) -I$(top_srcdir)/openbsd-compat
if NON_LINUX
AM_LDFLAGS = -lresolv
else
AM_LDFLAGS = -lresolv -lrt
endif
bin_PROGRAMS = bgpd
bgpd_SOURCES = bgpd.c session.c log.c logmsg.c parse.y config.c \
	       rde.c rde_rib.c rde_decide.c rde_prefix.c mrt.c kroute.c \
	       control.c pfkey.c rde_update.c rde_attr.c printconf.c \
	       rde_filter.c pftable.c name2id.c util.c carp.c timer.c
bgpd_LDADD = ../openbsd-compat/libopenbsdcompat.a $(AM_LDFLAGS)
