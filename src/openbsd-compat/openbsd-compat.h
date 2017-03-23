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
#elif __linux__
#include <endian.h>
#include <inttypes.h>
#else
#include <sys/endian.h>
#include <inttypes.h>
#endif /* defined(darwin) || defined(__APPLE__) || defined(MACOSX) */

#define betoh64(x)	(be64toh(x))
#define betoh32(x)	(be32toh(x))


/* bits		usage
 * ----		-----
 * 0-4		Media subtype
 * 5-7		Media type
 * 8-15		Type specific options
 * 16-31	General options
 */

/* Media types */

#define	IFM_ETHER		0x00000020	/* Ethernet */
#define	IFM_TOKEN		0x00000040	/* Token Ring */
#define	IFM_FDDI		0x00000060	/* Fiber Distributed Data Interface */
#define	IFM_IEEE80211	0x00000080	/* Wireless IEEE 802.11 */
#define IFM_ATM			0x000000a0
#ifndef IFM_CARP
/*
 * Common Access Redundancy Protocol
 */
#define	IFM_CARP		0x000000c0
#endif
#ifndef IFT_IEEE80211
#define IFT_IEEE80211		   0x47 /* radio spread spectrum	*/
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

#if __linux__
/* bgpd/kroute.c for linux */

/*
 * Address families.
 */
#ifndef AF_ROUTE
#define AF_ROUTE        17              /* Internal Routing Protocol */
#endif
#define AF_LINK         18              /* Link layer interface */

/*
 * PF_ROUTE - Routing table
 *
 * Four additional levels are defined:
 *		Fourth: address family, 0 is wildcard
 *		Fifth: type of info, defined below
 *		Sixth: flag(s) to mask with for NET_RT_FLAGS
 *		Seventh: routing table to use (facultative, defaults to 0)
 *				 NET_RT_TABLE has the table id as sixth element.
 */
#define NET_RT_DUMP 	1				/* dump; may limit to a.f. */
#define NET_RT_FLAGS	2				/* by flags, e.g. RESOLVING */
#define NET_RT_IFLIST	3				/* survey interface list */
#define NET_RT_STATS	4				/* routing table statistics */
#define NET_RT_TABLE	5
#define NET_RT_MAXID	6

#define	SO_USELOOPBACK	0x0040			/* bypass hardware when possible */
#define RTF_BLACKHOLE   0x1000          /* just discard pkts (during updates) */
#define RTF_LLINFO      0x400           /* generated by link layer (e.g. ARP) */
#define RTF_PROTO1      0x8000          /* protocol specific routing flag */
#define RTM_VERSION	5	/* Up the ante and ignore older versions */
/*
 * Message types.
 */
#define RTM_ADD         0x1     /* Add Route */
#define RTM_DELETE      0x2     /* Delete Route */
#define RTM_CHANGE      0x3     /* Change Metrics or flags */
#define RTM_GET         0x4     /* Report Metrics */
#define RTM_LOSING      0x5     /* Kernel Suspects Partitioning */
#define RTM_REDIRECT    0x6     /* Told to use different route */
#define RTM_MISS        0x7     /* Lookup failed on this address */
#define RTM_LOCK        0x8     /* fix specified metrics */
#define RTM_OLDADD      0x9     /* caused by SIOCADDRT */
#define RTM_OLDDEL      0xa     /* caused by SIOCDELRT */
#define RTM_RESOLVE     0xb     /* req to resolve dst to LL addr */
#define RTM_NEWADDR     0xc     /* address being added to iface */
#define RTM_DELADDR     0xd     /* address being removed from iface */
#define RTM_IFINFO      0xe     /* iface going up/down etc. */
#define RTM_NEWMADDR    0xf     /* mcast group membership being added to if */
#define RTM_DELMADDR    0x10    /* mcast group membership being deleted */
#define RTM_IFANNOUNCE  0x11    /* iface arrival/departure */

/*
 * Bitmask values for rtm_inits and rmx_locks.
 */
#define RTV_MTU         0x1     /* init or lock _mtu */
#define RTV_HOPCOUNT    0x2     /* init or lock _hopcount */
#define RTV_EXPIRE      0x4     /* init or lock _expire */
#define RTV_RPIPE       0x8     /* init or lock _recvpipe */
#define RTV_SPIPE       0x10    /* init or lock _sendpipe */
#define RTV_SSTHRESH    0x20    /* init or lock _ssthresh */
#define RTV_RTT         0x40    /* init or lock _rtt */
#define RTV_RTTVAR      0x80    /* init or lock _rttvar */

/*
 * Bitmask values for rtm_addrs.
 */
#define RTA_DST         0x1     /* destination sockaddr present */
#define RTA_GATEWAY		0x2		/* gateway sockaddr present */
#define RTA_NETMASK     0x4     /* netmask sockaddr present */
#define RTA_IFP         0x10    /* interface name sockaddr present */
#define RTM_IFINFO      0xe     /* iface going up/down etc. */
#define RTA_SRC			0x100	/* source sockaddr present */ 

/*
 * Index offsets for sockaddr array for alternate internal encoding.
 */
#define RTAX_DST        0       /* destination sockaddr present */
#define RTAX_GATEWAY    1       /* gateway sockaddr present */
#define RTAX_NETMASK    2       /* netmask sockaddr present */
#define RTAX_GENMASK    3       /* cloning mask sockaddr present */
#define RTAX_IFP        4       /* interface name sockaddr present */
#define RTAX_IFA        5       /* interface addr sockaddr present */
#define RTAX_AUTHOR     6       /* sockaddr for author of redirect */
#define RTAX_BRD        7       /* for NEWADDR, broadcast or p-p dest addr */
#define RTAX_MAX        8       /* size of array to allocate */

/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
struct if_data {
        /* Generic interface information */
        u_char ifi_type;                                /* Ethernet, tokenring, etc */
        u_char ifi_physical;                            /* E.g., AUI, Thinnet, 10base-T, etc */
        u_char ifi_addrlen;                             /* Media address length */
        u_char ifi_hdrlen;                              /* Media header length */
        u_char ifi_recvquota;                           /* Polling quota for receive intrs */
        u_char ifi_xmitquota;                           /* Polling quota for xmit intrs */
        u_long ifi_mtu;                                 /* Maximum transmission unit */
        u_long ifi_metric;                              /* Routing metric (external only) */
        u_long ifi_baudrate;                            /* Linespeed */
        /* Volatile statistics */
        u_long ifi_ipackets;                            /* Packets received on interface */
        u_long ifi_ierrors;                             /* Input errors on interface */
        u_long ifi_opackets;                            /* Packets sent on interface */
        u_long ifi_oerrors;                             /* Output errors on interface */
        u_long ifi_collisions;                          /* Collisions on csma interfaces */
        u_long ifi_ibytes;                              /* Total number of octets received */
        u_long ifi_obytes;                              /* Total number of octets sent */
        u_long ifi_imcasts;                             /* Packets received via multicast */
        u_long ifi_omcasts;                             /* Packets sent via multicast */
        u_long ifi_iqdrops;                             /* Dropped on input, this interface */
        u_long ifi_noproto;                             /* Destined for unsupported protocol */
        u_long ifi_hwassist;                            /* HW offload capabilities */
        u_long ifi_unused;                              /* XXX was ifi_xmittiming */
        struct timeval ifi_lastchange;          		/* Time of last administrative change */
};

/* Message format for use in obtaining information about interfaces from getkerninfo and the routing socket */
struct if_msghdr {
        u_short ifm_msglen;                     /* To skip over non-understood messages */
        u_char ifm_version;                     /* Future binary compatibility */
        u_char ifm_type;                        /* Message type */
        int     ifm_addrs;                      /* Like rtm_addrs */
        int     ifm_flags;                      /* Value of if_flags */
        u_short ifm_index;                      /* Index for associated ifp */
        struct if_data ifm_data;        		/* Statistics and other data about if */
};

/*
 * These numbers are used by reliable protocols for determining
 * retransmission behavior and are included in the routing structure.
 */
struct rt_metrics {
        u_long  rmx_locks;      /* Kernel must leave these values alone */
        u_long  rmx_mtu;        /* MTU for this path */
        u_long  rmx_hopcount;   /* max hops expected */
        u_long  rmx_expire;     /* lifetime for route, e.g. redirect */
        u_long  rmx_recvpipe;   /* inbound delay-bandwidth product */
        u_long  rmx_sendpipe;   /* outbound delay-bandwidth product */
        u_long  rmx_ssthresh;   /* outbound gateway buffer limit */
        u_long  rmx_rtt;        /* estimated round trip time */
        u_long  rmx_rttvar;     /* estimated rtt variance */
        u_long  rmx_pksent;     /* packets sent using this route */
        u_long  rmx_filler[4];  /* will be used for T/TCP later */
};

/*
 * Structures for routing messages.
 */
struct rt_msghdr {
        u_short rtm_msglen;     /* to skip over non-understood messages */
        u_char  rtm_version;    /* future binary compatibility */
        u_char  rtm_type;       /* message type */
        u_short rtm_index;      /* index for associated ifp */
        int     rtm_flags;      /* flags, incl. kern & message, e.g. DONE */
        int     rtm_addrs;      /* bitmask identifying sockaddrs in msg */
        pid_t   rtm_pid;        /* identify sender */
        int     rtm_seq;        /* for sender to identify action */
        int     rtm_errno;      /* why failed */
        int     rtm_use;        /* from rtentry */
        u_long  rtm_inits;      /* which metrics we are initializing */
        struct  rt_metrics rtm_rmx; /* metrics themselves */
};

/* Message format announcing the arrival or departure of a network interface. 
*/
struct if_announcemsghdr {
#ifndef IFNAMSIZ
# define IFNAMSIZ       16
#endif
        u_short ifan_msglen;            /* To skip over non-understood messages */
        u_char ifan_version;            /* Future binary compatibility */
        u_char ifan_type;               /* Message type */
        u_short ifan_index;             /* Index for associated ifp */
        char ifan_name[IFNAMSIZ];       /* If name, e.g. "en0" */
        u_short ifan_what;              /* What type of announcement */
};

/* bgpctl/bgpctl.c for linux */

/*
 * NetBSD extension not defined in the BSDI API.  This is used in various
 * places to get the canonical description for a given type/subtype.
 *
 * NOTE: all but the top-level type descriptions must contain NO whitespace!
 * Otherwise, parsing these in ifconfig(8) would be a nightmare.
 */
struct ifmedia_description {
	int	ifmt_word;		/* word value; may be masked */
	const char *ifmt_string;	/* description */
};

#define	IFM_TYPE_DESCRIPTIONS {						\
	{ IFM_ETHER,		"Ethernet" },				\
	{ IFM_TOKEN,		"Token ring" },				\
	{ IFM_FDDI,		"FDDI" },				\
	{ IFM_IEEE80211,	"IEEE 802.11 Wireless Ethernet" },	\
	{ 0, NULL },							\
}

/*
 * Interface types for benefit of parsing media address headers.
 * This list is derived from the SNMP list of ifTypes, currently
 * documented in RFC1573.
 */
#define	IFT_ETHER	0x6			/* Ethernet CSMACD */
#define	IFT_FDDI	0xf
#define	IFT_PPP		0x17		/* RFC 1331 */

extern int optreset;

#endif /* __linux__ */

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

#ifndef HAVE_GETENTROPY
int	getentropy(void *buf, size_t len);
#endif

#ifndef HAVE_ARC4RANDOM
void seed_rng(void);
unsigned int arc4random(void);
void arc4random_buf(void *_buf, size_t n);
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

#ifndef HAVE_INET_NET_PTON
int inet_net_pton(int af, const char *src, void *dst, size_t size);
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
