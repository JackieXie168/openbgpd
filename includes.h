/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OPENBGPD_INCLUDES_H
#define OPENBGPD_INCLUDES_H

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (char *)rcsid, "\100(#)" msg }

#include "config.h"
// #include "version.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <grp.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>	/* for bzero */
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h> /* For u_intXX_t */
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "defines.h"
#ifndef HAVE_SYS_QUEUE_H
#include "openbsd-compat/sys-queue.h"
#endif
#include "openbsd-compat/openbsd-compat.h"

#if defined(darwin) || defined(__APPLE__) || defined(MACOSX)
#include <errno.h>
#define XSPERR(x) ((x == 0) ? -1 : -x)

static __inline__ int setresgid(gid_t r, gid_t e, gid_t x)
{
   if (setgid(r) == -1)
      return XSPERR(errno);
   return setegid(e);
}

static __inline__ int setresuid(uid_t r, uid_t e, uid_t x)
{
   if (setuid(r) == -1)
      return XSPERR(errno);
   return seteuid(e);
}

static __inline__ int getresgid(gid_t *r, gid_t *e, gid_t *x)
{
  *r = getgid();
  *e = getegid();
  return 0;
}

static __inline__ int getresuid(uid_t *r, uid_t *e, uid_t *x)
{
  *r = getuid();
  *e = geteuid();
  return 0;
}
#endif

#endif /* OPENBGPD_INCLUDES_H */
