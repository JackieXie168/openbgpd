#ifndef __PBGPD_H__
#define __PBGPD_H__

#ifndef PBGPD
# define PBGPD  (1)
#endif

#include <pbgp.h>
#include "session.h"
#include "rde.h"

#define SETUP_PATH          "/etc/pbgp/"

#define STORE_SETUP_PUB     "store_setup_pub"
#define STORE_IBE           "store_ibe"
#define STORE_EPOCH         "store_epoch"
#define STORE_COUNTERS      "store_counters"

#define PBGPD_PREFIX        "[pbgpd] :: "

#define PBGPD_VERSION       5
#define PBGPD_CAPA          0xff

int
pbgpd_init(uint32_t as);

static __inline__ void pbgpd_msg(char * fmt, ...) {
#ifdef PBGPD_DEBUG
  if (errno && errno != EINVAL) {
      perror("[!] Last error: ");
  }
#endif
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, PBGPD_PREFIX);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  fflush(stderr);
}

#define PBGP_BENCHMARK 0
# define pbgp_debug(fmt...)

struct buf *
pbgpd_open_sign(u_int32_t local_as, u_int32_t remote_as);

int
pbgpd_open_verify(struct peer *p);

struct buf *
pbgpd_update_sign(struct attr *pkt, struct rde_peer *peer, struct rde_aspath *a,
                  struct bgpd_addr *prefix, u_int8_t prefixlen);

int
pbgpd_update_verify(struct attr *pkt, struct rde_peer *peer, struct rde_aspath *a,
                    struct bgpd_addr *prefix, u_int8_t prefixlen);

#endif
