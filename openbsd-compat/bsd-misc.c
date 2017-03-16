/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2004 Darren Tucker <dtucker at zip com au>
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

#include <errno.h>

#include "includes.h"

#ifdef HAVE_SYS_TIMEX_H
/*
 * We can't put this in includes.h because of conflicting definitions of
 * ntp_adjtime.
 */
# include <sys/timex.h>
#endif

#ifndef HAVE___PROGNAME
char *__progname;
#endif

static char *
xstrdup(char *s)
{
	char *c = strdup(s);

	if (c == NULL) {
		fprintf(stderr, "%s failed: %s", __func__, strerror(errno));
		exit(1);
	}
	return c;
}

/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
char *
_compat_get_progname(const char *argv0)
{
#ifdef HAVE___PROGNAME
	extern char *__progname;

	return xstrdup(__progname);
#else
	char *p;

	if (argv0 == NULL)
		return ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	if (p == NULL)
		p = argv0;
	else
		p++;

	return (xstrdup(p));
#endif
}

#if !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
int seteuid(uid_t euid)
{
	return (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#if !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
int setegid(uid_t egid)
{
	return(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ifndef HAVE_VSYSLOG
void
vsyslog(int priority, const char *message, va_list args)
{
	char buf[2048];

	vsnprintf(buf, sizeof(buf), message, args); /* possible truncation */
	syslog(priority, "%s", buf);
}
#endif /* HAVE_VSYSLOG */

#ifndef HAVE_CLOCK_GETRES
int
clock_getres(int clock_id, struct timespec *tp)
{
# ifdef HAVE_ADJTIMEX
	struct timex tmx;
# endif

	if (clock_id != CLOCK_REALTIME)
		return -1;	/* not implemented */
	tp->tv_sec = 0;

# ifdef HAVE_ADJTIMEX
	tmx.modes = 0;
	if (adjtimex(&tmx) == -1)
		return -1;
	else
		tp->tv_nsec = tmx.precision * 1000;	/* usec -> nsec */
# else
	/* assume default 10ms tick */
	tp->tv_nsec = 10000000;
# endif
	return 0;
}
#endif /* HAVE_CLOCK_GETRES */

#ifndef HAVE_EXPLICIT_BZERO
/*	$OpenBSD: explicit_bzero.c,v 1.3 2014/06/21 02:34:26 matthew Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include <string.h>

__attribute__((weak)) void
__explicit_bzero_hook(void *buf, size_t len)
{
}

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}
#endif /* HAVE_EXPLICIT_BZERO */

#ifndef HAVE_PLEDGE
/* Placed in the public domain.  */
/* Stub; real implementations wanted. */
int pledge(const char *promises, const char *paths[])
{
	return 0;
}

#endif /* HAVE_PLEDGE */

#ifndef HAVE_REALLOCARRAY
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* this is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW (1UL << (sizeof(size_t) * 4))

void *
reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
			nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}
#endif /*HAVE_REALLOCARRAY */

#ifndef HAVE_GETDTABLECOUNT
#if defined(__FreeBSD__) || defined(darwin) || defined(__APPLE__) || defined(MACOSX)
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stddef.h>

#define	KERN_PROC_NFDS		43	/* number of open file descriptors */

int getdtablecount(void);

/* 
 * Return the count of open file descriptors for this process.
 *
 */
int getdtablecount(void)
{
	int mib[4];
	int error;
	int nfds;
	size_t len;

	len = sizeof(nfds);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_NFDS;
	mib[3] = 0;

	error = sysctl(mib, 4, &nfds, &len, NULL, 0);
	if (error)
		return (-1);
	return (nfds);
}
#endif /* HAVE_GETDTABLECOUNT */
#endif /* BSD */

#ifndef HAVE_STRNVIS
#include <sys/types.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#ifdef __linux__
#include <linux-vis.h>

#define	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')

/*
 * vis - visually encode characters
 */
char *
vis(dst, c, flag, nextc)
	register char *dst;
	int c, nextc;
	register int flag;
{
	if (((u_int)c <= UCHAR_MAX && isascii(c) && isgraph(c)) ||
	   ((flag & VIS_SP) == 0 && c == ' ') ||
	   ((flag & VIS_TAB) == 0 && c == '\t') ||
	   ((flag & VIS_NL) == 0 && c == '\n') ||
	   ((flag & VIS_SAFE) && (c == '\b' || c == '\007' || c == '\r'))) {
		*dst++ = c;
		if (c == '\\' && (flag & VIS_NOSLASH) == 0)
			*dst++ = '\\';
		*dst = '\0';
		return (dst);
	}

	if (flag & VIS_CSTYLE) {
		switch(c) {
		case '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			goto done;
		case '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			goto done;
		case '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			goto done;
#if __STDC__
		case '\a':
#else
		case '\007':
#endif
			*dst++ = '\\';
			*dst++ = 'a';
			goto done;
		case '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			goto done;
		case '\t':
			*dst++ = '\\';
			*dst++ = 't';
			goto done;
		case '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			goto done;
		case ' ':
			*dst++ = '\\';
			*dst++ = 's';
			goto done;
		case '\0':
			*dst++ = '\\';
			*dst++ = '0';
			if (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			goto done;
		}
	}
	if (((c & 0177) == ' ') || (flag & VIS_OCTAL)) {	
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		goto done;
	}
	if ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	if (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	if (iscntrl(c)) {
		*dst++ = '^';
		if (c == 0177)
			*dst++ = '?';
		else
			*dst++ = c + '@';
	} else {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	return (dst);
}

/*
 * strvis, strvisx - visually encode characters from src into dst
 *	
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned. 
 *
 *	Strvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */
int
strvis(dst, src, flag)
	register char *dst;
	register const char *src;
	int flag;
{
	register char c;
	char *start;

	for (start = dst; (c = *src); )
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	return (dst - start);
}

int
strvisx(dst, src, len, flag)
	register char *dst;
	register const char *src;
	register size_t len;
	int flag;
{
	register char c;
	char *start;

	for (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	if (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';

	return (dst - start);
}

#else
#include <vis.h>
#endif

#ifndef VIS_ALL
#define	VIS_ALL	0x400 /* encode all characters */
#endif

#define	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_SAFE) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

int
strnvis(char *dst, const char *src, size_t siz, int flag)
{
	char *start, *end;
	char tbuf[5];
	int c, i;

	i = 0;
	for (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		if (isvisible(c, flag)) {
			i = 1;
			*dst++ = c;
			if (c == '\\' && (flag & VIS_NOSLASH) == 0) {
				/* need space for the extra '\\' */
				if (dst < end)
					*dst++ = '\\';
				else {
					dst--;
					i = 2;
					break;
				}
			}
			src++;
		} else {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			if (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} else {
				src--;
				break;
			}
		}
	}
	if (siz > 0)
		*dst = '\0';
	if (dst + i > end) {
		/* adjust return value for truncation */
		while ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	return (dst - start);
}
#endif /* HAVE_STRNVIS */

