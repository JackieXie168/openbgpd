/*	$OpenBSD$ */

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

#include <errno.h>
#include <pwd.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bgpd.h"
#include "ensure.h"
#include "mrt.h"
#include "rde.h"
#include "session.h"

#define	PFD_PIPE_MAIN		0
#define PFD_PIPE_SESSION	1

void		 rde_sighdlr(int);
void		 rde_dispatch_imsg_session(struct imsgbuf *);
void		 rde_dispatch_imsg_parent(struct imsgbuf *);
int		 rde_update_dispatch(struct imsg *);
int		 rde_update_get_prefix(u_char *, u_int16_t, struct bgpd_addr *,
		     u_int8_t *);
void		 init_attr_flags(struct attr_flags *);
int		 rde_update_get_attr(struct rde_peer *, u_char *, u_int16_t,
		     struct attr_flags *);
void		 rde_update_err(struct rde_peer *, enum suberr_update);
void		 rde_update_log(const char *,
		     const struct rde_peer *, const struct attr_flags *,
		     const struct bgpd_addr *, u_int8_t);
void		 rde_update_queue_runner(void);

void		 peer_init(struct peer *, u_int32_t);
struct rde_peer	*peer_add(u_int32_t, struct peer_config *);
void		 peer_remove(struct rde_peer *);
struct rde_peer	*peer_get(u_int32_t);
void		 peer_up(u_int32_t, struct session_up *);
void		 peer_down(u_int32_t);

void		 network_init(struct network_head *);
void		 network_add(struct network_config *);

volatile sig_atomic_t	 rde_quit = 0;
struct bgpd_config	*conf, *nconf;
time_t			 reloadtime;
struct rde_peer_head	 peerlist;
struct rde_peer		 peerself;
struct filter_head	*rules_l, *newrules;
struct imsgbuf		 ibuf_se;
struct imsgbuf		 ibuf_main;

int			 mrt_flagfilter = 0;
struct mrt_config	 mrt_filter;

void
rde_sighdlr(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		rde_quit = 1;
		break;
	}
}

u_int32_t	peerhashsize = 64;
u_int32_t	pathhashsize = 1024;
u_int32_t	nexthophashsize = 64;

int
rde_main(struct bgpd_config *config, struct peer *peer_l,
    struct network_head *net_l, struct filter_head *rules,
    int pipe_m2r[2], int pipe_s2r[2])
{
	pid_t		 pid;
	struct passwd	*pw;
	struct pollfd	 pfd[2];
	int		 n, nfds;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	conf = config;

	if ((pw = getpwnam(BGPD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot failed");
	chdir("/");

	setproctitle("route decision engine");
	bgpd_process = PROC_RDE;

	if (setgroups(1, &pw->pw_gid) ||
	    setegid(pw->pw_gid) || setgid(pw->pw_gid) ||
	    seteuid(pw->pw_uid) || setuid(pw->pw_uid)) {
		fatal("can't drop privileges");
	}

	endpwent();

	signal(SIGTERM, rde_sighdlr);
	signal(SIGINT, rde_sighdlr);

	close(pipe_s2r[0]);
	close(pipe_m2r[0]);

	/* initialize the RIB structures */
	imsg_init(&ibuf_se, pipe_s2r[1]);
	imsg_init(&ibuf_main, pipe_m2r[1]);

	pt_init();
	path_init(pathhashsize);
	nexthop_init(nexthophashsize);
	peer_init(peer_l, peerhashsize);
	rules_l = rules;
	network_init(net_l);

	log_info("route decision engine ready");

	while (rde_quit == 0) {
		bzero(&pfd, sizeof(pfd));
		pfd[PFD_PIPE_MAIN].fd = ibuf_main.sock;
		pfd[PFD_PIPE_MAIN].events = POLLIN;
		if (ibuf_main.w.queued > 0)
			pfd[PFD_PIPE_MAIN].events |= POLLOUT;

		pfd[PFD_PIPE_SESSION].fd = ibuf_se.sock;
		pfd[PFD_PIPE_SESSION].events = POLLIN;
		if (ibuf_se.w.queued > 0)
			pfd[PFD_PIPE_SESSION].events |= POLLOUT;

		if ((nfds = poll(pfd, 2, INFTIM)) == -1)
			if (errno != EINTR)
				fatal("poll error");

		if (nfds > 0 && (pfd[PFD_PIPE_MAIN].revents & POLLOUT) &&
		    ibuf_main.w.queued)
			if ((n = msgbuf_write(&ibuf_main.w)) < 0)
				fatal("pipe write error");

		if (nfds > 0 && pfd[PFD_PIPE_MAIN].revents & POLLIN) {
			nfds--;
			rde_dispatch_imsg_parent(&ibuf_main);
		}

		if (nfds > 0 && (pfd[PFD_PIPE_SESSION].revents & POLLOUT) &&
		    ibuf_se.w.queued)
			if ((n = msgbuf_write(&ibuf_se.w)) < 0)
				fatal("pipe write error");

		if (nfds > 0 && pfd[PFD_PIPE_SESSION].revents & POLLIN) {
			nfds--;
			rde_dispatch_imsg_session(&ibuf_se);
		}
		rde_update_queue_runner();
	}

	log_info("route decision engine exiting");
	_exit(0);
}

void
rde_dispatch_imsg_session(struct imsgbuf *ibuf)
{
	struct imsg		 imsg;
	struct session_up	 sup;
	int			 n;

	if ((n = imsg_read(ibuf)) == -1)
		fatal("rde_dispatch_imsg_session: imsg_read error");
	if (n == 0)	/* connection closed */
		fatal("rde_dispatch_imsg_session: pipe closed");

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("rde_dispatch_imsg_session: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_UPDATE:
			rde_update_dispatch(&imsg);
			break;
		case IMSG_SESSION_UP:
			if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(sup))
				fatalx("incorrect size of session request");
			memcpy(&sup, imsg.data, sizeof(sup));
			peer_up(imsg.hdr.peerid, &sup);
			break;
		case IMSG_SESSION_DOWN:
			peer_down(imsg.hdr.peerid);
			break;
		default:
			break;
		}
		imsg_free(&imsg);
	}
}

void
rde_dispatch_imsg_parent(struct imsgbuf *ibuf)
{
	struct imsg		 imsg;
	struct mrt_config	 mrt;
	struct peer_config	*pconf;
	struct rde_peer		*p, *np;
	struct filter_rule	*r;
	int			 n;

	if ((n = imsg_read(ibuf)) == -1)
		fatal("rde_dispatch_imsg_parent: imsg_read error");
	if (n == 0)	/* connection closed */
		fatal("rde_dispatch_imsg_parent: pipe closed");

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("rde_dispatch_imsg_parent: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_RECONF_CONF:
			reloadtime = time(NULL);
			newrules = calloc(1, sizeof(struct filter_head));
			if (newrules == NULL)
				fatal(NULL);
			TAILQ_INIT(newrules);
			if ((nconf = malloc(sizeof(struct bgpd_config))) ==
			    NULL)
				fatal(NULL);
			memcpy(nconf, imsg.data, sizeof(struct bgpd_config));
			break;
		case IMSG_RECONF_PEER:
			pconf = imsg.data;
			if ((p = peer_get(pconf->id)) == NULL)
				p = peer_add(pconf->id, pconf);
			else
				memcpy(&p->conf, pconf,
				    sizeof(struct peer_config));
			p->conf.reconf_action = RECONF_KEEP;
			break;
		case IMSG_RECONF_NETWORK:
			network_add(imsg.data);
			break;
		case IMSG_RECONF_FILTER:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct filter_rule))
				fatalx("IMSG_RECONF_FILTER bad len");
			if ((r = malloc(sizeof(struct filter_rule))) == NULL)
				fatal(NULL);
			memcpy(r, imsg.data, sizeof(struct filter_rule));
			TAILQ_INSERT_TAIL(newrules, r, entries);
			break;
		case IMSG_RECONF_DONE:
			if (nconf == NULL)
				fatalx("got IMSG_RECONF_DONE but no config");
			for (p = LIST_FIRST(&peerlist);
			    p != LIST_END(&peerlist); p = np) {
				np = LIST_NEXT(p, peer_l);
				switch (p->conf.reconf_action) {
				case RECONF_NONE:
					peer_remove(p);
					break;
				case RECONF_KEEP:
					/* reset state */
					p->conf.reconf_action = RECONF_NONE;
					break;
				default:
					break;
				}
			}
			memcpy(conf, nconf, sizeof(struct bgpd_config));
			free(nconf);
			nconf = NULL;
			prefix_network_clean(&peerself, reloadtime);
			while ((r = TAILQ_FIRST(rules_l)) != NULL) {
				TAILQ_REMOVE(rules_l, r, entries);
				free(r);
			}
			free(rules_l);
			rules_l = newrules;
			log_info("RDE reconfigured");
			break;
		case IMSG_NEXTHOP_UPDATE:
			nexthop_update(imsg.data);
			break;
		case IMSG_MRT_REQ:
			memcpy(&mrt, imsg.data, sizeof(mrt));
			mrt.msgbuf = &ibuf_main.w;
			if (mrt.type == MRT_TABLE_DUMP) {
				mrt_clear_seq();
				pt_dump(mrt_dump_upcall, &mrt);
				if (imsg_compose(&ibuf_main, IMSG_MRT_END,
				    mrt.id, NULL, 0) == -1)
					fatalx("imsg_compose error");
			} else if (mrt.type == MRT_FILTERED_IN) {
				mrt_flagfilter = 1;
				memcpy(&mrt_filter, &mrt, sizeof(mrt_filter));
			}
			break;
		case IMSG_MRT_END:
			memcpy(&mrt, imsg.data, sizeof(mrt));
			/* ignore end message because a dump is atomic */
			if (mrt.type == MRT_FILTERED_IN) {
				mrt_flagfilter = 0;
				bzero(&mrt_filter, sizeof(mrt_filter));
			}
			break;
		default:
			break;
		}
		imsg_free(&imsg);
	}
}

/* handle routing updates from the session engine. */
int
rde_update_dispatch(struct imsg *imsg)
{
	struct rde_peer		*peer;
	u_char			*p;
	int			 pos;
	u_int16_t		 len;
	u_int16_t		 withdrawn_len;
	u_int16_t		 attrpath_len;
	u_int16_t		 nlri_len;
	u_int8_t		 prefixlen;
	struct bgpd_addr	 prefix;
	struct attr_flags	 attrs;

	peer = peer_get(imsg->hdr.peerid);
	if (peer == NULL)	/* unknown peer, cannot happen */
		return (-1);
	if (peer->state != PEER_UP)
		return (-1);	/* peer is not yet up, cannot happen */

	if (mrt_flagfilter == 1)
		mrt_dump_bgp_msg(&mrt_filter, imsg->data,
		    imsg->hdr.len - IMSG_HEADER_SIZE, UPDATE,
		    &peer->conf, conf);

	p = imsg->data;

	memcpy(&len, p, 2);
	withdrawn_len = ntohs(len);
	p += 2;
	if (imsg->hdr.len < IMSG_HEADER_SIZE + 2 + withdrawn_len + 2) {
		rde_update_err(peer, ERR_UPD_ATTRLIST);
		return (-1);
	}

	while (withdrawn_len > 0) {
		if ((pos = rde_update_get_prefix(p, withdrawn_len, &prefix,
		    &prefixlen)) == -1) {
			rde_update_err(peer, ERR_UPD_ATTRLIST);
			return (-1);
		}
		p += pos;
		withdrawn_len -= pos;
		rde_update_log("withdraw", peer, NULL, &prefix, prefixlen);
		prefix_remove(peer, &prefix, prefixlen);
	}

	memcpy(&len, p, 2);
	attrpath_len = ntohs(len);
	p += 2;
	if (imsg->hdr.len <
	    IMSG_HEADER_SIZE + 2 + withdrawn_len + 2 + attrpath_len) {
		rde_update_err(peer, ERR_UPD_ATTRLIST);
		return (-1);
	}
	nlri_len =
	    imsg->hdr.len - IMSG_HEADER_SIZE - 4 - withdrawn_len - attrpath_len;
	if (attrpath_len == 0) /* 0 = no NLRI information in this message */
		return (0);

	init_attr_flags(&attrs);
	while (attrpath_len > 0) {
		if ((pos = rde_update_get_attr(peer, p, attrpath_len,
		    &attrs)) < 0) {
			rde_update_err(peer, ERR_UPD_ATTRLIST);
			return (-1);
		}
		p += pos;
		attrpath_len -= pos;
	}

	while (nlri_len > 0) {
		if ((pos = rde_update_get_prefix(p, nlri_len, &prefix,
		    &prefixlen)) == -1) {
			rde_update_err(peer, ERR_UPD_ATTRLIST);
			return (-1);
		}
		p += pos;
		nlri_len -= pos;
		rde_update_log("update", peer, &attrs, &prefix, prefixlen);
		if (peer->conf.max_prefix &&
		    peer->prefix_cnt >= peer->conf.max_prefix) {
			log_peer_warnx(&peer->conf, "prefix limit reached");
			rde_update_err(peer, ERR_UPD_UNSPECIFIC);
			break;
		}
		path_update(peer, &attrs, &prefix, prefixlen);
	}

	/* need to free allocated attribute memory that is no longer used */
	aspath_destroy(attrs.aspath);
	attr_optfree(&attrs);

	return (0);
}

int
rde_update_get_prefix(u_char *p, u_int16_t len, struct bgpd_addr *prefix,
    u_int8_t *prefixlen)
{
	int		i;
	u_int8_t	pfxlen;
	u_int16_t	plen;
	union {
		struct in_addr	a32;
		u_int8_t	a8[4];
	}		addr;

	if (len < 1)
		return (-1);

	memcpy(&pfxlen, p, 1);
	p += 1;
	plen = 1;

	addr.a32.s_addr = 0;
	for (i = 0; i <= 3; i++) {
		if (pfxlen > i * 8) {
			if (len - plen < 1)
				return (-1);
			memcpy(&addr.a8[i], p++, 1);
			plen++;
		}
	}
	prefix->af = AF_INET;
	prefix->v4.s_addr = addr.a32.s_addr;
	*prefixlen = pfxlen;

	return (plen);
}

#define UPD_READ(t, p, plen, n) \
	do { \
		memcpy(t, p, n); \
		p += n; \
		plen += n; \
	} while (0)

void
init_attr_flags(struct attr_flags *a)
{
	bzero(a, sizeof(struct attr_flags));
	a->origin = ORIGIN_INCOMPLETE;
	TAILQ_INIT(&a->others);
}

int
rde_update_get_attr(struct rde_peer *peer, u_char *p, u_int16_t len,
    struct attr_flags *a)
{
	u_int32_t	 tmp32;
	u_int16_t	 attr_len;
	u_int16_t	 plen = 0;
	u_int8_t	 flags;
	u_int8_t	 type;
	u_int8_t	 tmp8;
	int		 r; /* XXX */

	if (len < 3)
		return (-1);

	UPD_READ(&flags, p, plen, 1);
	UPD_READ(&type, p, plen, 1);

	if (flags & ATTR_EXTLEN) {
		if (len - plen < 2)
			return (-1);
		UPD_READ(&attr_len, p, plen, 2);
	} else {
		UPD_READ(&tmp8, p, plen, 1);
		attr_len = tmp8;
	}

	if (len - plen < attr_len)
		return (-1);

	switch (type) {
	case ATTR_UNDEF:
		/* error! */
		return (-1);
	case ATTR_ORIGIN:
		if (attr_len != 1)
			return (-1);
		UPD_READ(&a->origin, p, plen, 1);
		break;
	case ATTR_ASPATH:
		if ((r = aspath_verify(p, attr_len, conf->as)) != 0) {
			/* XXX could also be a aspath loop but this
			 * check should be moved to the filtering. */
			log_warnx("XXX aspath_verify failed: error %i", r);
			return (-1);
		}
		a->aspath = aspath_create(p, attr_len);
		plen += attr_len;
		break;
	case ATTR_NEXTHOP:
		if (attr_len != 4)
			return (-1);
		UPD_READ(&a->nexthop, p, plen, 4);	/* network byte order */
		break;
	case ATTR_MED:
		if (attr_len != 4)
			return (-1);
		UPD_READ(&tmp32, p, plen, 4);
		a->med = ntohl(tmp32);
		break;
	case ATTR_LOCALPREF:
		if (attr_len != 4)
			return (-1);
		if (peer->conf.ebgp) {
			/* ignore local-pref attr for non ibgp peers */
			a->lpref = 0;	/* set a default value */
			break;
		}
		UPD_READ(&tmp32, p, plen, 4);
		a->lpref = ntohl(tmp32);
		break;
	case ATTR_ATOMIC_AGGREGATE:
	case ATTR_AGGREGATOR:
	default:
		attr_optadd(a, flags, type, p, attr_len);
		plen += attr_len;
		break;
	}

	return (plen);

}

void
rde_update_err(struct rde_peer *peer, enum suberr_update errorcode)
{
	u_int8_t	errcode;

	errcode = errorcode;
	if (imsg_compose(&ibuf_se, IMSG_UPDATE_ERR, peer->conf.id,
	    &errcode, sizeof(errcode)) == -1)
		fatal("imsg_compose error");
	peer->state = PEER_ERR;
}

void
rde_update_log(const char *message,
    const struct rde_peer *peer, const struct attr_flags *attr,
    const struct bgpd_addr *prefix, u_int8_t prefixlen)
{
	char		*nexthop = NULL;
	struct in_addr	 nh;

	if (! (conf->log & BGPD_LOG_UPDATES))
		return;

	if (attr != NULL) {
		nh.s_addr = attr->nexthop;
		asprintf(&nexthop, " via %s", inet_ntoa(nh));
	}

	log_debug("neighbor %s (AS%u) %s %s/%u %s",
	    log_addr(&peer->conf.remote_addr), peer->conf.remote_as, message,
	    inet_ntoa(prefix->v4), prefixlen,
	    nexthop ? nexthop : "");

	free(nexthop);
}

/*
 * kroute specific functions
 */
void
rde_send_kroute(struct prefix *new, struct prefix *old)
{
	struct kroute	 kr;
	struct prefix	*p;
	enum imsg_type	 type;

	ENSURE(old == NULL || old->aspath->nexthop != NULL);
	ENSURE(new == NULL || new->aspath->nexthop != NULL);
	/*
	 * If old is != NULL we know it was active and should be removed.
	 * On the other hand new may be UNREACH and then we should not
	 * generate an update.
	 */
	if ((old == NULL || old->aspath->nexthop->flags & NEXTHOP_ANNOUNCE) &&
	    (new == NULL || new->aspath->nexthop->state != NEXTHOP_REACH ||
	    new->aspath->nexthop->flags & NEXTHOP_ANNOUNCE))
		return;

	if (new == NULL || new->aspath->nexthop == NULL ||
	    new->aspath->nexthop->state != NEXTHOP_REACH ||
	    new->aspath->nexthop->flags & NEXTHOP_ANNOUNCE) {
		type = IMSG_KROUTE_DELETE;
		p = old;
		kr.nexthop.s_addr = 0;
	} else {
		type = IMSG_KROUTE_CHANGE;
		p = new;
		kr.nexthop.s_addr = p->aspath->nexthop->true_nexthop.v4.s_addr;
	}

	kr.prefix.s_addr = p->prefix->prefix.v4.s_addr;
	kr.prefixlen = p->prefix->prefixlen;

	if (imsg_compose(&ibuf_main, type, 0, &kr, sizeof(kr)) == -1)
		fatal("imsg_compose error");
}

/*
 * nexthop specific functions
 */
void
rde_send_nexthop(struct bgpd_addr *next, int valid)
{
	int			type;

	if (valid)
		type = IMSG_NEXTHOP_ADD;
	else
		type = IMSG_NEXTHOP_REMOVE;

	if (imsg_compose(&ibuf_main, type, 0, next,
	    sizeof(struct bgpd_addr)) == -1)
		fatal("imsg_compose error");
}

/*
 * update specific functions
 */
u_char	queue_buf[4096];

void
rde_generate_updates(struct prefix *new, struct prefix *old)
{
	struct rde_peer			*peer;

	ENSURE(old == NULL || old->aspath->nexthop != NULL);
	ENSURE(new == NULL || new->aspath->nexthop != NULL);
	/*
	 * If old is != NULL we know it was active and should be removed.
	 * On the other hand new may be UNREACH and then we should not
	 * generate an update.
	 */
	if (old == NULL && (new == NULL ||
	    new->aspath->nexthop->state != NEXTHOP_REACH))
		return;

	LIST_FOREACH(peer, &peerlist, peer_l) {
		if (peer->state != PEER_UP)
			continue;
		up_generate_updates(peer, new, old);
	}
}

u_int16_t
rde_local_as(void)
{
	return conf->as;
}

void
rde_update_queue_runner(void)
{
	struct rde_peer		*peer;
	int			 r, sent;
	u_int16_t		 len, wd_len, wpos;

	len = sizeof(queue_buf) - MSGSIZE_HEADER;
	do {
		sent = 0;
		LIST_FOREACH(peer, &peerlist, peer_l) {
			if (peer->state != PEER_UP)
				continue;
			/* first withdraws */
			wpos = 2; /* reserve space for the lenght field */
			r = up_dump_prefix(queue_buf + wpos, len - wpos - 2,
			    &peer->withdraws, peer);
			wd_len = r;
			/* write withdraws lenght filed */
			wd_len = htons(wd_len);
			memcpy(queue_buf, &wd_len, 2);
			wpos += r;

			/* now bgp path attributes */
			r = up_dump_attrnlri(queue_buf + wpos, len - wpos,
			    peer);
			wpos += r;

			if (wpos == 4)
				/*
				 * No packet to send. The 4 bytes are the
				 * needed withdraw and path attribute lenght.
				 */
				continue;

			/* finally send message to SE */
			if (imsg_compose(&ibuf_se, IMSG_UPDATE, peer->conf.id,
			    queue_buf, wpos) == -1)
				fatal("imsg_compose error");
			sent++;
		}
	} while (sent != 0);
}


/*
 * peer functions
 */
struct peer_table {
	struct rde_peer_head	*peer_hashtbl;
	u_int32_t		 peer_hashmask;
} peertable;

#define PEER_HASH(x)		\
	&peertable.peer_hashtbl[(x) & peertable.peer_hashmask]

void
peer_init(struct peer *peer_l, u_int32_t hashsize)
{
	struct peer	*p, *next;
	u_int32_t	 hs, i;

	for (hs = 1; hs < hashsize; hs <<= 1)
		;
	peertable.peer_hashtbl = calloc(hs, sizeof(struct rde_peer_head));
	if (peertable.peer_hashtbl == NULL)
		fatal("peer_init");

	for (i = 0; i < hs; i++)
		LIST_INIT(&peertable.peer_hashtbl[i]);
	LIST_INIT(&peerlist);

	peertable.peer_hashmask = hs - 1;

	for (p = peer_l; p != NULL; p = next) {
		next = p->next;
		p->conf.reconf_action = RECONF_NONE;
		peer_add(p->conf.id, &p->conf);
		free(p);
	}
	peer_l = NULL;
}

struct rde_peer *
peer_get(u_int32_t id)
{
	struct rde_peer_head	*head;
	struct rde_peer		*peer;

	head = PEER_HASH(id);
	ENSURE(head != NULL);

	LIST_FOREACH(peer, head, hash_l) {
		if (peer->conf.id == id)
			return peer;
	}
	return NULL;
}

struct rde_peer *
peer_add(u_int32_t id, struct peer_config *p_conf)
{
	struct rde_peer_head	*head;
	struct rde_peer	*peer;

	ENSURE(peer_get(id) == NULL);

	peer = calloc(1, sizeof(struct rde_peer));
	if (peer == NULL)
		fatal("peer_add");

	LIST_INIT(&peer->path_h);
	memcpy(&peer->conf, p_conf, sizeof(struct peer_config));
	peer->remote_bgpid = 0;
	peer->state = PEER_NONE;
	up_init(peer);

	head = PEER_HASH(id);
	ENSURE(head != NULL);

	LIST_INSERT_HEAD(head, peer, hash_l);
	LIST_INSERT_HEAD(&peerlist, peer, peer_l);

	return (peer);
}

void
peer_remove(struct rde_peer *peer)
{
	/*
	 * If the session is up we wait until we get the IMSG_SESSION_DOWN
	 * message. If the session is down or was never up we delete the
	 * peer.
	 */
	if (peer->state == PEER_UP) {
		peer->conf.reconf_action = RECONF_DELETE;
	} else {
		ENSURE(peer_get(peer->conf.id) != NULL);
		ENSURE(LIST_EMPTY(&peer->path_h));

		LIST_REMOVE(peer, hash_l);
		LIST_REMOVE(peer, peer_l);

		free(peer);
	}
}

void
peer_up(u_int32_t id, struct session_up *sup)
{
	struct rde_peer	*peer;

	peer = peer_get(id);
	if (peer == NULL) {
		log_warnx("peer_up: unknown peer id %d", id);
		return;
	}

	ENSURE(peer->state == PEER_DOWN || peer->state == PEER_NONE);
	peer->remote_bgpid = ntohl(sup->remote_bgpid);
	memcpy(&peer->local_addr, &sup->local_addr, sizeof(peer->local_addr));
	memcpy(&peer->remote_addr, &sup->remote_addr,
	    sizeof(peer->remote_addr));
	peer->state = PEER_UP;
	up_init(peer);
	pt_dump(up_dump_upcall, peer);
}

void
peer_down(u_int32_t id)
{
	struct rde_peer		*peer;
	struct rde_aspath	*asp, *nasp;

	peer = peer_get(id);
	if (peer == NULL) {
		log_warnx("peer_down: unknown peer id &d", id);
		return;
	}
	peer->remote_bgpid = 0;
	peer->state = PEER_DOWN;
	up_down(peer);

	/* walk through per peer RIB list and remove all prefixes. */
	for (asp = LIST_FIRST(&peer->path_h);
	    asp != LIST_END(&peer->path_h);
	    asp = nasp) {
		nasp = LIST_NEXT(asp, peer_l);
		path_remove(asp);
	}
	LIST_INIT(&peer->path_h);

	if (peer->conf.reconf_action == RECONF_DELETE)
		peer_remove(peer);
}

/*
 * network announcement stuff
 */
void
network_init(struct network_head *net_l)
{
	struct network	*n;

	reloadtime = time(NULL);
	bzero(&peerself, sizeof(peerself));
	peerself.state = PEER_UP;
	peerself.remote_bgpid = conf->bgpid;
	peerself.conf.remote_as = conf->as;
	snprintf(peerself.conf.descr, sizeof(peerself.conf.descr),
	    "LOCAL AS %hu", conf->as);

	for (n = TAILQ_FIRST(net_l); n != TAILQ_END(net_l);
	    n = TAILQ_FIRST(net_l)) {
		TAILQ_REMOVE(net_l, n, network_l);
		network_add(&n->net);
		free(n);
	}
}

void
network_add(struct network_config *nc)
{
	struct attr_flags	 attrs;

	bzero(&attrs, sizeof(attrs));

	attrs.aspath = aspath_create(NULL, 0);
	attrs.nexthop = INADDR_ANY;
	/* med = 0 */
	/* lpref = 0 */
	attrs.origin = ORIGIN_IGP;
	TAILQ_INIT(&attrs.others);

	path_update(&peerself, &attrs, &nc->prefix, nc->prefixlen);
}

