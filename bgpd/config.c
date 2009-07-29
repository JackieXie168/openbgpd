/*	$OpenBSD: config.c,v 1.41 2005/03/15 14:40:08 henning Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sys-queue.h"
#include "bgpd.h"
#include "session.h"

u_int32_t	get_bgpid(void);
int		host_v4(const char *, struct bgpd_addr *, u_int8_t *);
int		host_v6(const char *, struct bgpd_addr *);

int
merge_config(struct bgpd_config *xconf, struct bgpd_config *conf,
    struct peer *peer_l, struct listen_addrs *listen_addrs)
{
	struct peer				*p;
	struct listen_addr			*la;
	int					 errs = 0;

	/* preserve cmd line opts */
	conf->opts = xconf->opts;

	if (!conf->as) {
		log_warnx("configuration error: AS not given");
		return (1);
	}

	if (!conf->min_holdtime)
		conf->min_holdtime = MIN_HOLDTIME;

	if (!conf->bgpid)
		conf->bgpid = get_bgpid();

	if ((conf->flags & BGPD_FLAG_REFLECTOR) && conf->clusterid == 0)
		conf->clusterid = conf->bgpid;

	for (p = peer_l; p != NULL; p = p->next) {
		p->conf.ebgp = (p->conf.remote_as != conf->as);
		if (p->conf.announce_type == ANNOUNCE_UNDEF)
			p->conf.announce_type = p->conf.ebgp == 0 ?
			    ANNOUNCE_ALL : ANNOUNCE_SELF;
		if (p->conf.enforce_as == ENFORCE_AS_UNDEF)
			p->conf.enforce_as = p->conf.ebgp == 0 ?
			    ENFORCE_AS_OFF : ENFORCE_AS_ON;
		if (p->conf.reflector_client && p->conf.ebgp) {
			log_peer_warnx(&p->conf, "configuration error: "
			    "EBGP neighbors are not allowed in route "
			    "reflector clusters");
			return (1);
		}
	}

	if (xconf->listen_addrs != NULL) {
		while ((la = TAILQ_FIRST(xconf->listen_addrs)) != NULL) {
			TAILQ_REMOVE(xconf->listen_addrs, la, entry);
			free(la);
		}
		free(xconf->listen_addrs);
	}

	memcpy(xconf, conf, sizeof(struct bgpd_config));

	xconf->listen_addrs = listen_addrs;

	return (errs);
}

u_int32_t
get_bgpid(void)
{
	struct ifaddrs		*ifap, *ifa;
	u_int32_t		 ip = 0, cur, localnet;

	localnet = inet_addr("127.0.0.0");

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		cur = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
		if ((cur & localnet) == localnet)	/* skip 127/8 */
			continue;
		if (cur > ip)
			ip = cur;
	}
	freeifaddrs(ifap);

	return (ip);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}

	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}

	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		log_warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}

	return (0);
}

int
host(const char *s, struct bgpd_addr *h, u_int8_t *len)
{
	int			 done = 0;
	int			 mask;
	char			*p, *q, *ps;

	if ((p = strrchr(s, '/')) != NULL) {
		errno = 0;
		mask = strtol(p+1, &q, 0);
		if (errno == ERANGE || !q || *q || mask > 128 || q == (p+1)) {
			log_warnx("invalid netmask");
			return (0);
		}
		if ((ps = malloc(strlen(s) - strlen(p) + 1)) == NULL)
			fatal("host: malloc");
		strlcpy(ps, s, strlen(s) - strlen(p) + 1);
	} else {
		if ((ps = strdup(s)) == NULL)
			fatal("host: strdup");
		mask = 128;
	}

	bzero(h, sizeof(struct bgpd_addr));

	/* IPv4 address? */
	if (!done)
		done = host_v4(s, h, len);

	/* IPv6 address? */
	if (!done) {
		done = host_v6(ps, h);
		*len = mask;
	}

	free(ps);

	return (done);
}

int
host_v4(const char *s, struct bgpd_addr *h, u_int8_t *len)
{
	struct in_addr		 ina;
	int			 bits = 32;

	bzero(&ina, sizeof(struct in_addr));
	if (strrchr(s, '/') != NULL) {
		if ((bits = inet_net_pton(AF_INET, s, &ina, sizeof(ina))) == -1)
			return (0);
	} else {
		if (inet_pton(AF_INET, s, &ina) != 1)
			return (0);
	}

	h->af = AF_INET;
	h->v4.s_addr = ina.s_addr;
	*len = bits;

	return (1);
}

int
host_v6(const char *s, struct bgpd_addr *h)
{
	struct addrinfo		 hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, "0", &hints, &res) == 0) {
		h->af = AF_INET6;
		memcpy(&h->v6,
		    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		    sizeof(h->v6));
		h->scope_id =
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;

		freeaddrinfo(res);
		return (1);
	}

	return (0);
}

void
prepare_listeners(struct bgpd_config *conf)
{
	struct listen_addr	*la, *next;
	int			 opt = 1;

	if (TAILQ_EMPTY(conf->listen_addrs)) {
		if ((la = calloc(1, sizeof(struct listen_addr))) == NULL)
			fatal("setup_listeners calloc");
		la->fd = -1;
		la->flags = DEFAULT_LISTENER;
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
		la->sa.ss_len = sizeof(struct sockaddr_in);
#endif
		((struct sockaddr_in *)&la->sa)->sin_family = AF_INET;
		((struct sockaddr_in *)&la->sa)->sin_addr.s_addr =
		    htonl(INADDR_ANY);
		((struct sockaddr_in *)&la->sa)->sin_port = htons(BGP_PORT);
		TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);

		if ((la = calloc(1, sizeof(struct listen_addr))) == NULL)
			fatal("setup_listeners calloc");
		la->fd = -1;
		la->flags = DEFAULT_LISTENER;
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
		la->sa.ss_len = sizeof(struct sockaddr_in6);
#endif
		((struct sockaddr_in6 *)&la->sa)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&la->sa)->sin6_port = htons(BGP_PORT);
		TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);
	}

	for (la = TAILQ_FIRST(conf->listen_addrs); la != NULL; la = next) {
		next = TAILQ_NEXT(la, entry);
		if ((la->fd = socket(la->sa.ss_family, SOCK_STREAM,
		    IPPROTO_TCP)) == -1) {
			if (la->flags & DEFAULT_LISTENER && (errno ==
			    EAFNOSUPPORT || errno == EPROTONOSUPPORT)) {
				TAILQ_REMOVE(conf->listen_addrs, la, entry);
				free(la);
				continue;
			} else
				fatal("socket");
		}

//		opt = 1;
//		if (setsockopt(la->fd, SOL_SOCKET, SO_REUSEPORT,
//		    &opt, sizeof(opt)) == -1)
//			fatal("setsockopt SO_REUSEPORT");

		if (bind(la->fd, (struct sockaddr *)&la->sa, SS_LEN(la->sa)) ==
		    -1) {
			log_warn("cannot bind to %s",
			    log_sockaddr((struct sockaddr *)&la->sa));
			close(la->fd);
			TAILQ_REMOVE(conf->listen_addrs, la, entry);
			free(la);
			continue;
		}
	}
}