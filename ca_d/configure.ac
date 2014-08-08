AC_PREREQ([2.65])
AC_INIT(libpbgp, 0.0.1, d.spinelli@naitec.it)
AM_INIT_AUTOMAKE

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/pbgp_setup.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Check unit test suite
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CHECK_LIB([ssl],[SSL_connect])
# AC_CHECK_LIB([db],[db_open])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h])

# openbsd does not need it
AC_CHECK_LIB(resolv, inet_net_pton, , AC_MSG_WARN([resolv lib not found]))

AC_CHECK_LIB(db, db_create, , AC_MSG_ERROR([Berkeley db library not found]))
AC_CHECK_LIB(crypto, EVP_PKEY_new, , AC_MSG_ERROR([OpenSSL library not found]))
AC_CHECK_LIB(gmp, __gmpz_random, , AC_MSG_ERROR([GMP lib not found]))
AC_CHECK_LIB(pbc, pbc_init_random, , AC_MSG_ERROR([PBC lib not found]))

# non compulsory
AC_CHECK_LIB(uuid, uuid_generate, , AC_MSG_WARN([uuid lib not found]))
AC_CHECK_LIB(e2fs-uuid, uuid_generate, , AC_MSG_WARN([uuid lib not found]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([bzero gettimeofday memset strerror strrchr strtol])

AC_OUTPUT([Makefile src/Makefile tests/Makefile benchmarks/Makefile])
