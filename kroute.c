/*	$OpenBSD$ */

/*
 * Copyright (c) 2003 Henning Brauer <henning@openbsd.org>
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bgpd.h"

struct kroute_node {
	RB_ENTRY(kroute_node)	entry;
	struct kroute		r;
	int			flags;
};

int	kroute_msg(int, int, struct kroute *);
int	kroute_compare(struct kroute_node *, struct kroute_node *);
void	get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
int	kroute_fetchtable(void);

RB_HEAD(kroute_tree, kroute_node)	kroute_tree, krt;
RB_PROTOTYPE(kroute_tree, kroute_node, entry, kroute_compare);
RB_GENERATE(kroute_tree, kroute_node, entry, kroute_compare);

u_int32_t		rtseq = 1;

#define	F_BGPD_INSERTED		0x0001
#define F_KERNEL		0x0002

int
kroute_init(void)
{
	int	s, opt;

	if ((s = socket(AF_ROUTE, SOCK_RAW, 0)) < 0)
		fatal("route socket", errno);

	/* not intrested in my own messages */
	if (setsockopt(s, SOL_SOCKET, SO_USELOOPBACK, &opt, sizeof(opt)) == -1)
		fatal("route setsockopt", errno);

	RB_INIT(&krt);

	kroute_fetchtable();

	return (s);
}

int
kroute_msg(int fd, int action, struct kroute *kroute)
{
	struct {
		struct rt_msghdr	hdr;
		struct sockaddr_in	prefix;
		struct sockaddr_in	nexthop;
		struct sockaddr_in	mask;
	} r;
	ssize_t	n;

	bzero(&r, sizeof(r));
	r.hdr.rtm_msglen = sizeof(r);
	r.hdr.rtm_version = RTM_VERSION;
	r.hdr.rtm_type = action;
	r.hdr.rtm_flags = RTF_GATEWAY|RTF_PROTO1; /* XXX */
	r.hdr.rtm_seq = rtseq++;	/* overflow doesn't matter */
	r.hdr.rtm_addrs = RTA_DST|RTA_GATEWAY|RTA_NETMASK;
	r.prefix.sin_len = sizeof(r.prefix);
	r.prefix.sin_family = AF_INET;
	r.prefix.sin_addr.s_addr = kroute->prefix;
	r.nexthop.sin_len = sizeof(r.nexthop);
	r.nexthop.sin_family = AF_INET;
	r.nexthop.sin_addr.s_addr = kroute->nexthop;
	r.mask.sin_len = sizeof(r.mask);
	r.mask.sin_family = AF_INET;
	r.mask.sin_addr.s_addr = htonl(0xffffffff << (32 - kroute->prefixlen));

retry:
	if ((n = write(fd, &r, sizeof(r))) == -1) {
		switch (errno) {
		case ESRCH:
			if (r.hdr.rtm_type == RTM_CHANGE) {
				r.hdr.rtm_type = RTM_ADD;
				goto retry;
			} else if (r.hdr.rtm_type == RTM_DELETE) {
				logit(LOG_INFO, "route vanished before delete");
				return (0);
			} else			/* nexthop invalid */
				return (-1);
			break;
		case EEXIST:	/* connected route */
			return (-2);
		default:
			logit(LOG_INFO, "kroute_msg: %s", strerror(errno));
			return (-1);
		}
	}
	if (n == sizeof(r))
		return (0);

	/* XXX we could not write everything... bad bad bad. cope. */
	return (n);
}

int
kroute_change(int fd, struct kroute *kroute)
{
	struct kroute_node	*kr, s;
	int			 n;
	int			 action = RTM_ADD;

	s.r.prefix = kroute->prefix;
	s.r.prefixlen = kroute->prefixlen;

	if ((kr = RB_FIND(kroute_tree, &krt, &s)) != NULL) {
		if (kr->flags & F_BGPD_INSERTED)
			action = RTM_CHANGE;
		else
			return (0);
	}

	if ((n = kroute_msg(fd, action, kroute)) == -1)
		return (-1);

	if (action == RTM_ADD) {
		if ((kr = calloc(1, sizeof(struct kroute_node))) == NULL)
			fatal(NULL, errno);

		kr->r.prefix = kroute->prefix;
		kr->r.prefixlen = kroute->prefixlen;
		kr->r.nexthop = kroute->nexthop;
		kr->flags = F_BGPD_INSERTED;

		if (RB_INSERT(kroute_tree, &krt, kr) != NULL) {
			logit(LOG_CRIT, "RB_INSERT failed!");
			return (-1);
		}
	} else
		kr->r.nexthop = kroute->nexthop;

	return (n);
}

int
kroute_delete(int fd, struct kroute *kroute)
{
	struct kroute_node	*kr, s;
	int			 n;

	s.r.prefix = kroute->prefix;
	s.r.prefixlen = kroute->prefixlen;

	if ((kr = RB_FIND(kroute_tree, &krt, &s)) == NULL) {
		/* at the moment this is totally valid... */
		log_kroute(LOG_CRIT, "kroute_delete: no match for", kroute);
		return (0);
	}

	if (!(kr->flags & F_BGPD_INSERTED))
		return (0);

	if ((n = kroute_msg(fd, RTM_DELETE, kroute)) == -1)
		return (-1);

	RB_REMOVE(kroute_tree, &krt, kr);
	free(kr);

	return (0);
}

int
kroute_compare(struct kroute_node *a, struct kroute_node *b)
{
	if (a->r.prefix < b->r.prefix)
		return (-1);
	if (a->r.prefix > b->r.prefix)
		return (1);
	if (a->r.prefixlen < b->r.prefixlen)
		return (-1);
	if (a->r.prefixlen > b->r.prefixlen)
		return (1);
	return (0);
}

void
kroute_shutdown(int fd)
{
	struct kroute_node	*kr;

	RB_FOREACH(kr, kroute_tree, &krt)
		if ((kr->flags & F_BGPD_INSERTED))
			kroute_msg(fd, RTM_DELETE, &kr->r);
}

#define	ROUNDUP(a, size)	\
    (((a) & ((size) - 1)) ? (1 + ((a) | ((size) - 1))) : (a))

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len, sizeof(long)));
		} else
			rti_info[i] = NULL;
	}
}

int
kroute_fetchtable(void)
{
	size_t			 len;
	int			 mib[6];
	char			*buf, *next, *lim;
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	struct sockaddr_in	*sa_in;
	struct kroute_node	*kr;
	in_addr_t		 ina;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
		fatal("sysctl", errno);
	if ((buf = malloc(len)) == NULL)
		fatal("kroute_fetchtable", errno);
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1)
		fatal("sysctl", errno);

	lim = buf + len;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sa = (struct sockaddr *)(rtm + 1);
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

		if ((sa_in = (struct sockaddr_in *)rti_info[RTAX_DST]) == NULL)
			continue;

		if (rtm->rtm_flags & RTF_LLINFO)
			continue;

		if ((kr = calloc(1, sizeof(struct kroute_node))) == NULL)
			fatal(NULL, errno);

		kr->r.prefix = sa_in->sin_addr.s_addr;
		if ((sa_in = (struct sockaddr_in *)rti_info[RTAX_NETMASK]) !=
		    NULL) {
			kr->r.prefixlen =
			    33 - ffs(ntohl(sa_in->sin_addr.s_addr));
			if (sa_in->sin_addr.s_addr == 0 || kr->r.prefix == 0)
				kr->r.prefixlen = 0;
		} else if (rtm->rtm_flags & RTF_HOST)
			kr->r.prefixlen = 32;
		else {
			/* classfull... */
			ina = ntohl(kr->r.prefix);

			if (ina >= 0xf0000000)		/* class E */
				kr->r.prefixlen = 32;
			else if (ina >= 0xe0000000)	/* class D */
				kr->r.prefixlen = 4;
			else if (ina >= 0xc0000000)	/* class C */
				kr->r.prefixlen = 24;
			else if (ina >= 0x80000000)	/* class B */
				kr->r.prefixlen = 16;
			else					/* class A */
				kr->r.prefixlen = 8;
		}

		if ((sa_in = (struct sockaddr_in *)rti_info[RTAX_GATEWAY]) !=
		    NULL)
			kr->r.nexthop = sa_in->sin_addr.s_addr;

		kr->flags = F_KERNEL;

		if (RB_INSERT(kroute_tree, &krt, kr) != NULL) {
			logit(LOG_CRIT, "RB_INSERT failed!");
			return (-1);
		}
	}
	free(buf);
	return (0);
};
