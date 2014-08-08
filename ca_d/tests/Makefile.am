AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_builddir)/includes -I$(top_srcdir)/includes
# AM_CFLAGS = -O3 -Wall -g -ggdb -fomit-frame-pointer

TESTS = check_main

check_PROGRAMS = check_main

check_main_LDADD = ${top_builddir}/bin/libpbgp.la @CHECK_LIBS@

check_main_SOURCES = check_void.c check_setup.c check_rsa.c check_main.c check_store.c\
		     check_ibe.c check_accwitt.c check_epoch.c

check_main_CFLAGS = @CHECK_CFLAGS@ -O3 -Wall -g -ggdb
# -Q -ftime-report -pg -fprofile-arcs -ftest-coverage

CLEANFILES = test_* __db* log.* core callgrind.out.* *.env

