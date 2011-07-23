/*
 * $hrs: openbgpd/openbsd-compat/openbsd-compat.h,v 1.6 2011/07/03 04:46:38 hrs Exp $
 */

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#define	__dead

/* for asprintf() and others */
#ifdef __GLIBC__
#define _GNU_SOURCE 1
#endif

/* setproctitle() and others from libbsd */
#ifdef __GLIBC__
#include <bsd/unistd.h>
#endif /* __GLIBC__ */

/* strlcpy() */
#ifdef __GLIBC__
#include <bsd/string.h>
#endif

/* for setgroups() */
#ifdef __GLIBC__
#define _BSD_SOURCE 1
#include <grp.h>
#endif

/* for poll() */
#ifdef __GLIBC__
#define INFTIM ((int) -1)
#endif

/* bgpctl/bgpctl.c */
#include <sys/endian.h>
#define betoh64(x)	(be64toh(x))

/* bgpd/irrfilter.c */
typedef unsigned long	ulong;

/* bgpd/bgpd.c */
#ifndef	RTLABEL_LEN	/* defined in net/pfvar.h */
#define RTLABEL_LEN	32
#endif
#define RTA_LABEL	0

#if defined(__FreeBSD__) /* not GNU/kFreeBSD */
#define SIMPLEQ_FOREACH         STAILQ_FOREACH
#define SIMPLEQ_FIRST           STAILQ_FIRST
#define SIMPLEQ_REMOVE_HEAD     STAILQ_REMOVE_HEAD
#define SIMPLEQ_INSERT_TAIL     STAILQ_INSERT_TAIL
#define SIMPLEQ_ENTRY           STAILQ_ENTRY
#define SIMPLEQ_HEAD            STAILQ_HEAD
#define SIMPLEQ_INIT            STAILQ_INIT
#define SIMPLEQ_HEAD_INITIALIZER	STAILQ_HEAD_INITIALIZER
#endif

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
#define RTP_DOWN        0x80    /* route/link is down */

/* missing LINK_STATE_* macros in net/if.h */
#define LINK_STATE_INVALID	LINK_STATE_UNKNOWN	/* link invalid */
#define LINK_STATE_KALIVE_DOWN	7	/* keepalive reports down */
#define LINK_STATE_HALF_DUPLEX	5	/* link is up and half duplex */
#define LINK_STATE_FULL_DUPLEX	6	/* link is up and full duplex */

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
#endif /* _OPENBSD_COMPAT_H */
