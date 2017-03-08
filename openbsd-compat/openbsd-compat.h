/* $Id: openbsd-compat.h,v 1.12 2004/12/03 02:17:50 dtucker Exp $ */

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
#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#include <pwd.h>
#include <netdb.h>

#include "includes.h"

#define __dead

/* bgpctl/bgpctl.c */
#if defined(darwin) || defined(__APPLE__) || defined(MACOSX)
#if 1
#include "osx_endian.h"
#else
#include <machine/endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#ifndef be16toh
#define be16toh(x)	((u_int16_t)(x))
#endif
#ifndef htobe16
#define htobe16(x)	((u_int16_t)(x))
#endif
#ifndef be32toh
#define be32toh(x)	((u_int32_t)(x))
#endif
#ifndef htobe32
#define htobe32(x)	((u_int32_t)(x))
#endif
#ifndef be64toh
#define be64toh(x)	((u_int64_t)(x))
#endif
#ifndef htobe64
#define htobe64(x)	((u_int64_t)(x))
#endif
#ifndef BE16TOH
#define BE16TOH(x)	((void)0)
#endif
#ifndef HTOBE16
#define HTOBE16(x)	((void)0)
#endif
#ifndef BE32TOH
#define BE32TOH(x)	((void)0)
#endif
#ifndef HTOBE32
#define HTOBE32(x)	((void)0)
#endif
#ifndef BE64TOH
#define BE64TOH(x)	((void)0)
#endif
#ifndef HTOBE64
#define HTOBE64(x)	((void)0)
#endif
#else /* little-endian */
#ifndef be16toh
#define be16toh(x)	((u_int16_t)ntohs((u_int16_t)(x)))
#endif
#ifndef htobe16
#define htobe16(x)	((u_int16_t)htons((u_int16_t)(x)))
#endif
#ifndef be32toh
#define be32toh(x)	((u_int32_t)ntohl((u_int32_t)(x)))
#endif
#ifndef htobe32
#define htobe32(x)	((u_int32_t)htonl((u_int32_t)(x)))
#endif
#ifndef be64toh
#ifdef __bswap_64 /* glibc */
#define be64toh(x)	((u_int64_t)__bswap_64((u_int64_t)(x)))
#else /* no __bswap_64 */
#ifdef __swab64 /* Linux kernel headers (libc5, at least with kernel 2.2) */
#define be64toh(x)	((u_int64_t)__swab64((u_int64_t)(x)))
#else /* no __bswap_64 or __swab64 */
static __inline__ u_int64_t be64toh(u_int64_t __x);
static __inline__ u_int64_t be64toh(u_int64_t __x) { return (((u_int64_t)be32toh(__x & (u_int64_t)0xFFFFFFFFULL)) << 32) | ((u_int64_t)be32toh((__x & (u_int64_t)0xFFFFFFFF00000000ULL) >> 32)); }
#define be64toh(x)	be64toh((x))
#endif /* no __bswap_64 or __swab64 */
#endif /* no __bswap_64 */
#endif /* no be64toh */
#ifndef htobe64
#define htobe64(x)	be64toh(x)
#endif
#ifndef BE16TOH
#define BE16TOH(x)	((x) = be16toh((x)))
#endif
#ifndef HTOBE16
#define HTOBE16(x)	((x) = htobe16((x)))
#endif
#ifndef BE32TOH
#define BE32TOH(x)	((x) = be32toh((x)))
#endif
#ifndef HTOBE32
#define HTOBE32(x)	((x) = htobe32((x)))
#endif
#ifndef BE64TOH
#define BE64TOH(x)	((x) = be64toh((x)))
#endif
#ifndef HTOBE64
#define HTOBE64(x)	((x) = htobe64((x)))
#endif
#endif /* little-endian */
#endif
#else
#include <sys/endian.h>
#include <inttypes.h>
#endif /* defined(darwin) || defined(__APPLE__) || defined(MACOSX) */

#define betoh64(x)	(be64toh(x))
#define betoh32(x)	(be32toh(x))

#ifndef IFT_IEEE80211
#define IFT_IEEE80211		   0x47 /* radio spread spectrum	*/
#endif
#ifndef IFM_CARP
/*
 * Common Access Redundancy Protocol
 */
#define	IFM_CARP		0x000000c0
#endif
#ifndef IFT_CARP
#define	IFT_CARP	0xf8
#endif

#define IF_Kbps(x)      ((uintmax_t)(x) * 1000) /* kilobits/sec. */
#define IF_Mbps(x)      (IF_Kbps((x) * 1000))   /* megabits/sec. */
#define IF_Gbps(x)      (IF_Mbps((x) * 1000))   /* gigabits/sec. */


/* Ignore all DEF_STRONG/DEF_WEAK in OpenBSD. */
#define DEF_STRONG(sym)
#define DEF_WEAK(sym)

#define IPSP_DIRECTION_IN       0x1
#define IPSP_DIRECTION_OUT      0x2

#ifndef AF_MPLS
#define AF_MPLS	33	/* XXX: collides with AF_NETBIOS, see sys/socket.h */
#endif

#ifndef MPLS_OP_PUSH
#define MPLS_OP_PUSH		0x2
#endif

#ifndef RTF_MPLS
#define RTF_MPLS      0x100000  /* MPLS additional infos */ 
#endif

/*
 * Structure of a SHIM header.
 */
#define MPLS_LABEL_MAX		((1 << 20) - 1)

struct shim_hdr {
	u_int32_t shim_label;	/* 20 bit label, 4 bit exp & BoS, 8 bit TTL */
};

#define MPLS_HDRLEN	sizeof(struct shim_hdr)

/*
 * Socket address
 */

struct sockaddr_mpls {
	u_int8_t	smpls_len;		/* length */
	u_int8_t	smpls_family;		/* AF_MPLS */
	u_int16_t	smpls_pad0;
	u_int32_t	smpls_label;		/* MPLS label */
	u_int32_t	smpls_pad1[2];
};


/* bgpd/bgpd.c */
#ifndef	RTLABEL_LEN	/* defined in net/pfvar.h */
#define RTLABEL_LEN	32
#endif
#define RTA_LABEL 0

/* Routing priorities used by the different routing protocols */
#define RTP_NONE        0       /* unset priority use sane default */
#define RTP_CONNECTED   4       /* directly connected routes */
#define RTP_STATIC      8       /* static routes base priority */
#define RTP_OSPF        32      /* OSPF routes */
#define RTP_ISIS        36      /* IS-IS routes */
#define RTP_RIP         40      /* RIP routes */
#define RTP_BGP         48      /* BGP routes */
#define RTP_DEFAULT     56      /* routes that have nothing set */
#define RTP_MAX         63      /* maximum priority */
#define RTP_ANY         64      /* any of the above */
#define RTP_MASK        0x7f
#define RTP_DOWN 0x80 /* route/link is down */

/*
 * setsockopt defines used for the filtering.
 */
#define ROUTE_MSGFILTER	1	/* bitmask to specifiy which types should be
				   sent to the client. */
#define ROUTE_TABLEFILTER 2	/* change routing table the socket is listening
				   on, RTABLE_ANY listens on all tables. */

#define ROUTE_FILTER(m)	(1 << (m))
#define RTABLE_ANY	0xffffffff

#define RTAX_LABEL	10		/* route label present */ 

#define RTF_CONNECTED 0x800000	/* interface route */

#define	IFAN_ARRIVAL	0	/* interface arrival */
#define	IFAN_DEPARTURE	1	/* interface departure */

/* missing LINK_STATE_* macros in net/if.h */
#define LINK_STATE_INVALID	LINK_STATE_UNKNOWN	/* link invalid */
#define LINK_STATE_KALIVE_DOWN	7	/* keepalive reports down */
#define LINK_STATE_HALF_DUPLEX	5	/* link is up and half duplex */
#define LINK_STATE_FULL_DUPLEX	6	/* link is up and full duplex */

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC O_CLOEXEC
#endif
#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK O_NONBLOCK
#endif


#define SADB_AALG_MD5HMAC				2
#define SADB_AALG_SHA1HMAC				3
#define SADB_EALG_3DESCBC				3
#define SADB_X_FLOW_TYPE_REQUIRE		3
#define SADB_X_SATYPE_TCPSIGNATURE		8
#define SADB_X_EALG_AES					12
#define SADB_X_ADDFLOW     			12
#define SADB_X_DELFLOW     			13
#define SADB_X_EXT_SRC_MASK			17
#define SADB_X_EXT_DST_MASK			18
#define SADB_X_EXT_PROTOCOL			19
#define SADB_X_EXT_FLOW_TYPE			20
#define SADB_X_EXT_SRC_FLOW			21
#define SADB_X_EXT_DST_FLOW			22

struct sadb_protocol {
	uint16_t sadb_protocol_len;
	uint16_t sadb_protocol_exttype;
	uint8_t  sadb_protocol_proto;
	uint8_t  sadb_protocol_direction;
	uint8_t  sadb_protocol_flags;
	uint8_t  sadb_protocol_reserved2;
};


/*
 * Values for if_link_state.
 */
#define LINK_STATE_UNKNOWN	0	/* link invalid/unknown */
#define LINK_STATE_DOWN		1	/* link is down */
#define LINK_STATE_UP		2	/* link is up */

/*
 * Status bit descriptions for the various interface types.
 */
struct if_status_description {
	unsigned char	ifs_type;
	unsigned char	ifs_state;
	const char *ifs_string;
};

#define LINK_STATE_DESC_MATCH(_ifs, _t, _s)				\
	(((_ifs)->ifs_type == (_t) || (_ifs)->ifs_type == 0) &&		\
	    (_ifs)->ifs_state == (_s))

#define LINK_STATE_DESCRIPTIONS {					\
	{ IFT_ETHER, LINK_STATE_DOWN, "no carrier" },			\
									\
	{ IFT_IEEE80211, LINK_STATE_DOWN, "no network" },		\
									\
	{ IFT_PPP, LINK_STATE_DOWN, "no carrier" },			\
									\
	{ IFT_CARP, LINK_STATE_DOWN, "backup" },			\
	{ IFT_CARP, LINK_STATE_UP, "master" },				\
	{ IFT_CARP, LINK_STATE_HALF_DUPLEX, "master" },			\
	{ IFT_CARP, LINK_STATE_FULL_DUPLEX, "master" },			\
									\
	{ 0, LINK_STATE_UP, "active" },					\
	{ 0, LINK_STATE_HALF_DUPLEX, "active" },			\
	{ 0, LINK_STATE_FULL_DUPLEX, "active" },			\
									\
/*	{ 0, LINK_STATE_UNKNOWN, "unknown" },	*/			\
	{ 0, LINK_STATE_INVALID, "invalid" },				\
	{ 0, LINK_STATE_DOWN, "down" },					\
	{ 0, LINK_STATE_KALIVE_DOWN, "keepalive down" },		\
	{ 0, 0, NULL }							\
}

char *_compat_get_progname(const char *);

#ifndef HAVE_ARC4RANDOM
void seed_rng(void);
unsigned int arc4random(void);
void arc4random_stir(void);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#ifndef HAVE_ASPRINTF
int      asprintf(char **, const char *, ...)
                __attribute__((__format__ (printf, 2, 3)));
#endif

#ifndef HAVE_INET_PTON
int inet_pton(int, const char *, void *);
#endif

#if !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
int seteuid(uid_t);
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#if !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
int setegid(uid_t);
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#ifndef HAVE_VSYSLOG
void vsyslog(int, const char *, va_list);
#endif

#ifndef HAVE_SNPRINTF
int snprintf(char *, size_t, const char *, ...);
#endif

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list);
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
void compat_init_setproctitle(int argc, char *argv[]);
#endif

#ifndef HAVE_CLOCK_GETRES
# ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME	1
# endif
int clock_getres(int, struct timespec *);
#endif

int permanently_set_uid(struct passwd *);

#ifndef set_binary_mode
#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
typedef enum {false = 0, true = 1} bool;
#endif
bool set_binary_mode (int, bool);
# if ! HAVE_SETMODE_DOS
#  define set_binary_mode(fd, mode) 1
# endif
#endif

#ifndef HAVE_ACCEPT4
int accept4 (int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
#endif

#ifndef HAVE_GETDTABLECOUNT
int getdtablecount(void);
#endif

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *buf, size_t len);
#endif

#ifndef HAVE_PLEDGE
int pledge(const char *promises, const char *paths[]);
#endif /* HAVE_PLEDGE */

#ifndef HAVE_REALLOCARRAY
void * reallocarray(void *optr, size_t nmemb, size_t size);
#endif

#ifndef HAVE_STRNVIS
int strnvis(char *dst, const char *src, size_t siz, int flag);
#endif

#endif /* _OPENBSD_COMPAT_H */
