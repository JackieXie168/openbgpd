AM_CFLAGS = -I. -I.. -I$(top_srcdir) -I$(top_srcdir)/bgpd
noinst_LIBRARIES = libopenbsdcompat.a
libopenbsdcompat_a_SOURCES = bsd-accept4.c bsd-misc.c bsd-snprintf.c uidswap.c asprintf.c \
			     daemon.c inet_pton.c strlcpy.c setproctitle.c strtonum.c \
			     fmt_scaled.c strlcat.c siphash.c imsg.c imsg-buffer.c
if NON_LINUX
# Do nothing
else
libopenbsdcompat_a_SOURCES += linkaddr.c sha512c.c getentropy_linux.c arc4random.c fgetln.c
endif

if HAVE_INET_NET_PTON
# Do nothing
else
libopenbsdcompat_a_SOURCES += inet_net_pton.c
endif