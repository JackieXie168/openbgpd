/*	$OpenBSD: pftable.c,v 1.10 2017/01/24 04:22:42 benno Exp $ */

/*
 * Copyright (c) 2004 Damien Miller <djm@openbsd.org>
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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#if !(defined(darwin) || defined(__APPLE__) || defined(MACOSX) || __linux__)
#include <net/pfvar.h>
#else
#include <sys/param.h>
#define	PF_TABLE_NAME_SIZE	 32
struct pfr_table {
	char			 pfrt_anchor[MAXPATHLEN];
	char			 pfrt_name[PF_TABLE_NAME_SIZE];
	u_int32_t		 pfrt_flags;
	u_int8_t		 pfrt_fback;
};

struct pfr_addr {
	union {
		struct in_addr		_pfra_ip4addr;
		struct in6_addr	_pfra_ip6addr;
	}		 pfra_u;
	u_int8_t	 pfra_af;
	u_int8_t	 pfra_net;
	u_int8_t	 pfra_not;
	u_int8_t	 pfra_fback;
};

enum { PFR_DIR_IN, PFR_DIR_OUT, PFR_DIR_MAX };
enum { PFR_OP_BLOCK, PFR_OP_PASS, PFR_OP_ADDR_MAX, PFR_OP_TABLE_MAX };
#define PFR_OP_XPASS	PFR_OP_ADDR_MAX

struct pfr_astats {
	struct pfr_addr	 pfras_a;
	u_int64_t	 pfras_packets[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	u_int64_t	 pfras_bytes[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	u_int64_t	 pfras_tzero;
};

struct pfioc_table {
	struct pfr_table	pfrio_table;
	void				*pfrio_buffer	__attribute__((aligned(8)));
	int			 		pfrio_esize	__attribute__((aligned(8)));
	int			 		pfrio_size;
	int			 		pfrio_size2;
	int			 		pfrio_nadd;
	int			 		pfrio_ndel;
	int			 		pfrio_nchange;
	int			 		pfrio_flags;
	u_int32_t		 	pfrio_ticket;
};

#define	DIOCRCLRADDRS	_IOWR('D', 66, struct pfioc_table)
#define	DIOCRADDADDRS	_IOWR('D', 67, struct pfioc_table)
#define	DIOCRDELADDRS	_IOWR('D', 68, struct pfioc_table)
#define	DIOCRGETASTATS	_IOWR('D', 71, struct pfioc_table)
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "log.h"
#include "bgpd.h"

/* Namespace collision: these are defined in both bgpd.h and pfvar.h */
#undef v4
#undef v6
#undef addr8
#undef addr16
#undef addr32

static int devpf = -1;

struct pf_table {
	LIST_ENTRY(pf_table)	entry;
	char			name[PFTABLE_LEN];
	unsigned long		what;
	struct pfr_addr		*worklist;
	int			naddrs;
	int			nalloc;
};

/* List of tables under management */
LIST_HEAD(, pf_table) tables = LIST_HEAD_INITIALIZER(tables);

static int
pftable_change(struct pf_table *pft)
{
	struct pfioc_table tio;
	int ret;

	if (pft->naddrs == 0 || pft->what == 0)
		return (0);

	if (devpf == -1 && ((devpf = open("/dev/pf", O_RDWR)) == -1))
		fatal("open(/dev/pf)");

	bzero(&tio, sizeof(tio));
	strlcpy(tio.pfrio_table.pfrt_name, pft->name,
	    sizeof(tio.pfrio_table.pfrt_name));
	tio.pfrio_buffer = pft->worklist;
	tio.pfrio_esize = sizeof(*pft->worklist);
	tio.pfrio_size = pft->naddrs;

	ret = ioctl(devpf, pft->what, &tio);

	/* bad prefixes shouldn't cause us to die */
	if (ret == -1) {
		if (errno == EINVAL)
			return (0);
		log_warn("pftable_change ioctl");
	}

	return (ret);
}

static int
pftable_clear(const char *name)
{
	struct pfioc_table tio;

	if (devpf == -1 && ((devpf = open("/dev/pf", O_RDWR)) == -1))
		fatal("open(/dev/pf)");

	bzero(&tio, sizeof(tio));
	strlcpy(tio.pfrio_table.pfrt_name, name,
	    sizeof(tio.pfrio_table.pfrt_name));

	if (ioctl(devpf, DIOCRCLRADDRS, &tio) != 0) {
		log_warn("pftable_clear ioctl");
		return (-1);
	}

	return (0);
}

int
pftable_exists(const char *name)
{
	struct pfioc_table tio;
	struct pfr_astats dummy;

	if (devpf == -1 && ((devpf = open("/dev/pf", O_RDWR)) == -1))
		fatal("open(/dev/pf)");

	bzero(&tio, sizeof(tio));
	strlcpy(tio.pfrio_table.pfrt_name, name,
	    sizeof(tio.pfrio_table.pfrt_name));
	tio.pfrio_buffer = &dummy;
	tio.pfrio_esize = sizeof(dummy);
	tio.pfrio_size = 1;

	if (ioctl(devpf, DIOCRGETASTATS, &tio) != 0)
		return (-1);

	return (0);
}

int
pftable_add(const char *name)
{
	struct pf_table *pft;

	/* Ignore duplicates */
	LIST_FOREACH(pft, &tables, entry)
		if (strcmp(pft->name, name) == 0)
			return (0);

	if ((pft = malloc(sizeof(*pft))) == NULL) {
		log_warn("pftable malloc");
		return (-1);
	}

	bzero(pft, sizeof(*pft));
	if (strlcpy(pft->name, name, sizeof(pft->name)) >= sizeof(pft->name)) {
		log_warn("pf_table name too long");
		free(pft);
		return (-1);
	}

	LIST_INSERT_HEAD(&tables, pft, entry);

	return (0);
}

int
pftable_clear_all(void)
{
	struct pf_table *pft;

	LIST_FOREACH(pft, &tables, entry) {
		if (pftable_clear(pft->name) != 0)
			return (-1);
		free(pft->worklist);
		pft->worklist = NULL;
		pft->nalloc = pft->naddrs = 0;
		pft->what = 0;
	}

	return (0);
}

static int
pftable_add_work(const char *table, struct bgpd_addr *addr,
    u_int8_t len, int del)
{
	struct pf_table *pft;
	struct pfr_addr *pfa, *tmp;
	unsigned long what;

	if (*table == '\0' || len > 128)
		fatal("pftable_add_work: insane");

	/* Find table */
	LIST_FOREACH(pft, &tables, entry)
		if (strcmp(pft->name, table) == 0)
			break;

	if (pft == NULL) {
		log_warn("pf table %s not found", table);
		return (-1);
	}

	/* Only one type of work on the list at a time */
	what = del ? DIOCRDELADDRS : DIOCRADDADDRS;
	if (pft->naddrs != 0 && pft->what != what)
		fatal("attempt to mix pf table additions/deletions");

	if (pft->nalloc <= pft->naddrs)
		pft->nalloc = pft->nalloc == 0 ? 1 : pft->nalloc * 2;
	tmp = reallocarray(pft->worklist, pft->nalloc, sizeof(*tmp));
	if (tmp == NULL) {
		if (pft->worklist != NULL) {
			log_warn("pftable_add_work: malloc");
			free(pft->worklist);
			pft->worklist = NULL;
		}
		pft->nalloc = pft->naddrs = 0;
		pft->what = 0;
		return (-1);
	}
	pft->worklist = tmp;
	pfa = &pft->worklist[pft->naddrs];

	bzero(pfa, sizeof(*pfa));
	memcpy(&pfa->pfra_u, &addr->ba, (len + 7U) / 8);
	pfa->pfra_af = aid2af(addr->aid);
	pfa->pfra_net = len;

	pft->naddrs++;
	pft->what = what;

	/* Don't let the list grow too large */
	if (pft->naddrs >= 1024)
		pftable_commit();

	return (0);
}

/* imsg handlers */
int
pftable_addr_add(struct pftable_msg *m)
{
	return (pftable_add_work(m->pftable, &m->addr, m->len, 0));
}

int
pftable_addr_remove(struct pftable_msg *m)
{
	return (pftable_add_work(m->pftable, &m->addr, m->len, 1));
}

int
pftable_commit(void)
{
	struct pf_table *pft;
	int ret = 0;

	LIST_FOREACH(pft, &tables, entry) {
		if (pft->what != 0 && pftable_change(pft) != 0)
			ret = -1;
		free(pft->worklist);
		pft->worklist = NULL;
		pft->nalloc = pft->naddrs = 0;
		pft->what = 0;
	}

	return (ret);
}

