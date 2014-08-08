AUTOMAKE_OPTIONS = foreign

# INCLUDES = -I. -I/usr/local/include/ -I/usr/include/
INCLUDES = -I${top_builddir}/includes

# AM_CFLAGS =
# CLEANFILES =

AM_CFLAGS = -O3 -Wall -Wextra -g -ggdb -std=c99 -fomit-frame-pointer
AM_CPPFLAGS = -D_GNU_SOURCE

# crawler_LDFLAGS = -L${top_builddir}/itxlib

lib_LTLIBRARIES = ${top_builddir}/bin/libpbgp.la

__top_builddir__bin_libpbgp_la_SOURCES = pbgp_setup.c pbgp_store.c pbgp_rsa.c pbgp_witness.c \
					 pbgp_accumulator.c pbgp_ibe.c pbgp_epoch.c pbgp_actions.c

# __top_builddir__bin_libpbgp_la_LDFLAGS = -shared -module -fPIC -Wl,--no-undefined

__top_builddir__bin_libpbgp_la_LIBADD = @CHECK_LIBS@
# -lpbc -lgmp -lssl -lcrypto -lresolv -ldb
