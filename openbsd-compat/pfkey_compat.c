#include "bgpd.h"
#include "session.h"

int
pfkey_establish(struct peer *p)
{
	if (p->conf.auth.method)
		return (-1);
	return (0);
}

int
pfkey_remove(struct peer *p)
{
        if (p->conf.auth.method)
                return (-1);
        return (0);
}

int
pfkey_init(struct bgpd_sysdep *sysdep)
{
	log_warnx("no kernel support for PF_KEY");
	sysdep->no_pfkey = 1;
	return (-1);
}

int
pfkey_read(int sd, struct sadb_msg *h)
{
	return (1);
}
