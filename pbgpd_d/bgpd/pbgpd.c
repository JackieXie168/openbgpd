#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pbgp.h>
#include <bgpd.h>
#include "pbgpd.h"
#include "session.h"
#include "rde.h"
#include "imsg.h"

/*******************************************************************************
 *
 *      __GLOBALS__ (STATIC)
 */
epoch_t                 *g_epoch;

static element_t        g_witness;

// public setup params
static setup_params_t   *g_setup;

// AS private ibe key
static ibe_keypair_t    *g_ibe_keypair;

static store_t
  // (global) setup params and CA public keys
  *g_store_setup_pub,

  // (global) accumulator and RSA signatures on revoked / added AS numbers
  *g_store_epoch,

  // (global) epoch list of added AS
  *g_store_added,

  // (global) epoch list of revoked AS
  *g_store_revoked,

  // (private) witness and CA sign on cidr(s)
  *g_store_envelope,

  // (private) counter storage
  *g_store_counters
;

/*************** __UTILS__ *****************************************************/

/*
 *    microseconds = 1 / 1 000 000 sec.
 */
static double
__timediff(struct timeval startTime, struct timeval endTime)
{
  return (endTime.tv_sec * 1000000  + (endTime.tv_usec)) -
         (startTime.tv_sec * 1000000 + (startTime.tv_usec));
}

static int
_compare(const void *aa, const void *bb)
{
  assert(aa && bb);

  const int *a = aa;
  const int *b = bb;

  if (*a == *b) {
    return 0;
  }

  if (*a < *b) {
    return -1;
  }

  return 1;
}

/**
 *  Check that AS numbers in UPDATE packet contains AS number in signed message.
 *    @return 0 if match (ok)
 */
static int
_check_aspath(const struct rde_aspath *a, u_int32_t *as_, size_t ascount_)
{
  u_int32_t as[MAX_PKTSIZE / sizeof(u_int32_t)],
            ascount = 0;

  u_int16_t seg_size = 0;
  u_int8_t i, *seg = a->aspath->data;
  u_int16_t len = a->aspath->len;

  // Traverse path and build AS list
  while (len > 1) {
    u_int8_t seg_type  = seg[0];

    // @postponed handle AS_SET
    if (AS_SEQUENCE != seg_type) {
      break ;
    }

    // how many entries for this seq
    u_int8_t seg_len = seg[1];

    // total length in bytes
    seg_size = 2 + sizeof(u_int32_t) * seg_len;

    if (len < seg_size) {
      break ;
    }

    for (i = 0; i < seg_len; i++) {
      as[ascount++] = aspath_extract(seg, i);
    }

    len -= seg_size;
    seg += seg_size;
  }

  assert(ascount >= ascount_);

  qsort(as, ascount, sizeof(u_int32_t), _compare);
  // pbgp_debug("%s", pbgp_rsa_bin2hex((unsigned char *) as, ascount * sizeof(u_int32_t)));

  qsort(as_, ascount_, sizeof(u_int32_t), _compare);
  // pbgp_debug("%s", pbgp_rsa_bin2hex((unsigned char *) as_, ascount_ * sizeof(u_int32_t)));

  return memcmp(as, as_, MIN(ascount, ascount_) * sizeof(u_int32_t));
}

/*******************************************************************************/

int
pbgpd_init(uint32_t asnum)
{
  pbgpd_msg("pbgpd_init :: start");

  g_store_setup_pub = pbgp_store_open(SETUP_PATH STORE_SETUP_PUB);
  g_store_epoch = pbgp_store_open(SETUP_PATH STORE_EPOCH);
  g_store_counters = pbgp_store_open(SETUP_PATH STORE_COUNTERS);

  g_store_added = pbgp_store_open(NULL);
  g_store_revoked = pbgp_store_open(NULL);

  g_setup = pbgp_setup_init(USHRT_MAX);
  pbgp_setup_load_pubkey(g_setup, g_store_setup_pub);

  // reads epoch data (accumulator / added / revoked)
  pbgp_epoch_init(&g_epoch, g_setup);
  pbgp_epoch_load(g_store_epoch, g_epoch, g_store_added, g_store_revoked);

  unsigned char hash[EVP_MAX_MD_SIZE + 1];
  unsigned int hsize = 0;

  // verify epoch rsa signature on added list
  memset(hash, 0, sizeof hash);
  hsize = pbgp_rsa_uhash_list_keys(g_store_added, hash);
  int verified = pbgp_rsa_verify(g_setup->rsa_evp, hash, hsize, g_epoch->signature_added, g_epoch->signature_added_len);

  if (verified != 1) {
    fatalx("pbgpd_init :: epoch signature on added asnum not verified");
  }

  // verify epoch rsa signature on revoked list
  memset(hash, 0, sizeof hash);
  hsize = pbgp_rsa_uhash_list_keys(g_store_revoked, hash);
  verified = pbgp_rsa_verify(g_setup->rsa_evp, hash, hsize, g_epoch->signature_revoked, g_epoch->signature_revoked_len);

  if (verified != 1) {
    fatalx("pbgpd_init :: epoch signature on revoked asnum not verified");
  }

  // reads witness (join data) from signed envelope
  char *store_name = pbgp_generate_envelope_storage_name(asnum);
  char store_path[strlen(SETUP_PATH) + strlen(store_name) + 1];
  snprintf(store_path, sizeof (store_path), "%s%s", SETUP_PATH, store_name);
  xfree(store_name);

  g_store_envelope = pbgp_store_open(store_path);

  uint32_t client_asnum;
  unsigned char *client_envelope_signature;
  size_t client_envelope_signature_size = 0;

  // read ibe keypair stored into envelope
  pbgp_ibe_keypair_init(g_setup, &g_ibe_keypair);
  pbgp_ibe_load_keypair(g_store_envelope, g_ibe_keypair);

  // load asnum, witness, signature from envelope for this asnum
  pbgp_join_load(g_setup, g_store_envelope, &client_asnum, &g_witness,
                 &client_envelope_signature, &client_envelope_signature_size);

  if (client_asnum != asnum) {
    fatalx("pbgpd_init :: envelope asnum mismatch");
  }

  // compute serialized = (asnum + witness) to check rsa signature on them
  unsigned char serialized[sizeof asnum + element_length_in_bytes(g_witness)];
  memcpy(serialized, &client_asnum, sizeof client_asnum);
  element_to_bytes(serialized + sizeof client_asnum, g_witness);

  // verify envelope rsa signature on serialized(asnum, witness)
  int ret = pbgp_rsa_verify(g_setup->rsa_evp, serialized, sizeof serialized,
                            client_envelope_signature, client_envelope_signature_size);

  if (ret != 1) {
    fatalx("pbgpd_init :: envelope signature not verified");
  }

  // update witness with epoch added / revoked as number
  pbgp_witness_update(g_setup, g_store_added, g_store_revoked, client_asnum, g_witness);

  // ret = 0 if __not__ revoked (id into accumulator)
  ret = pbgp_is_revoked(g_setup, asnum, g_epoch->accumulator, g_witness);

  if (ret != 0) {
    fatalx("pbgpd_init :: AS number is revoked");
  }

  pbgpd_msg("pbgpd_init :: success");
  return EXIT_SUCCESS;
}

#ifdef PBGPD
__attribute__((destructor)) static
void
pbgpd_finalize(void)
{
  pbgpd_msg("pbgpd_finalize :: cleanup");

  pbgp_epoch_clear(g_epoch);
  pbgp_setup_clear(&g_setup);

  pbgp_store_close(g_store_setup_pub);
  pbgp_store_close(g_store_envelope);
  pbgp_store_close(g_store_counters);
  pbgp_store_close(g_store_epoch);

  pbgp_store_close(g_store_added);
  pbgp_store_close(g_store_revoked);
}
#endif

/******** OPEN ****************************************************************/

/**
 * session_main -> session_dispatch_message(OPEN)
 *  -> bgp_fsm(EVNT_RCVD_OPEN) -> pbgpd_open_sign()
 */
struct buf *
pbgpd_open_sign(u_int32_t local_as, u_int32_t remote_as)
{
  time_t timestamp = time(NULL);
  u_int32_t witness_size = element_length_in_bytes(g_witness);

  /* serialize stored witness for local asnum */

  size_t buflen = sizeof(local_as) + sizeof(remote_as)
    + sizeof(timestamp) + sizeof(u_int32_t) + witness_size;

  struct buf *buf = buf_dynamic(buflen, MAX_PKTSIZE);
  if (!buf) {
    return NULL;
  }

  unsigned char _witbuf[witness_size];
  element_to_bytes(_witbuf, g_witness);

  buf_add(buf, &local_as, sizeof(local_as));
  buf_add(buf, &remote_as, sizeof(remote_as));
  buf_add(buf, &timestamp, sizeof(timestamp));
  buf_add(buf, &witness_size, sizeof(witness_size));
  buf_add(buf, &_witbuf, sizeof(_witbuf));

  assert(buf->size == buflen);

  ibe_signature_t *ibe_signature;
  pbgp_ibe_signature_init(g_setup, &ibe_signature);
  pbgp_ibe_sign(g_setup, g_ibe_keypair, buf->buf, buf->size, ibe_signature);

  size_t slen = pbgp_ibe_serialized_signature_size(ibe_signature);

  unsigned char _ibuf[slen];
  pbgp_ibe_signature_serialize(ibe_signature, _ibuf);

  buf_add(buf, &_ibuf, slen);

  pbgp_ibe_signature_clear(ibe_signature);

  return buf;
}

/**
 * session_main -> session_dispatch_message(SECUREOPEN)
 *   -> pbgpd_open_verify() -> bgp_fsm(EVNT_EVNT_RCVD_SECUREOPEN)
 */
int
pbgpd_open_verify(struct peer *p)
{
  size_t len = 0;
  unsigned char *buffer = p->rbuf->rptr;

  // unsigned short datalen = 0;
  // memcpy(&datalen, buffer + MSGSIZE_HEADER_MARKER, sizeof(datalen));
  // datalen = ntohs(datalen) - MSGSIZE_HEADER;

  buffer += MSGSIZE_HEADER;

  u_int32_t remote_as;
  memcpy(&remote_as, buffer, sizeof(remote_as));
  assert(len += sizeof(remote_as) < READ_BUF_SIZE);
  buffer += sizeof(remote_as);

  u_int32_t local_as;
  memcpy(&local_as, buffer, sizeof(local_as));
  assert(len += sizeof(local_as) < READ_BUF_SIZE);
  buffer += sizeof(local_as);

  time_t timestamp;
  memcpy(&timestamp, buffer, sizeof(timestamp));
  assert(len += sizeof(timestamp) < READ_BUF_SIZE);
  buffer += sizeof(timestamp);

  size_t witness_size;
  memcpy(&witness_size, buffer, sizeof(witness_size));
  assert(len += sizeof(witness_size) < READ_BUF_SIZE);
  buffer += sizeof(witness_size);

  element_t rcv_witness;
  element_init_G1(rcv_witness, g_setup->pairing);
  element_from_bytes(rcv_witness, buffer);
  assert(len += witness_size < READ_BUF_SIZE);
  buffer += witness_size;

  ibe_signature_t *ibe_signature;
  pbgp_ibe_signature_init(g_setup, &ibe_signature);
  pbgp_ibe_signature_unserialize(buffer, ibe_signature);

  store_t *message_store = pbgp_store_open(NULL);
  store_key_t key = STORE_KEY_INIT;

  size_t blen = sizeof(local_as) + sizeof(remote_as) + sizeof(timestamp) + sizeof(witness_size) + witness_size;

  // rewind buffer pointer (point to start of data)
  buffer = p->rbuf->rptr + MSGSIZE_HEADER;

  pbgp_store_put(message_store, STORE_KEY_SET_DATA(key, MESSAGE, remote_as), (void *) buffer, blen);

  int verified = !pbgp_ibe_verify(g_setup, ibe_signature, message_store);
  if (verified) {
    pbgpd_msg("pbgpd_open_verify :: verified (%d)", remote_as);
  }
  else {
    pbgpd_msg("pbgpd_open_verify :: not verified (%d)", remote_as);
  }

  pbgp_ibe_signature_clear(ibe_signature);
  pbgp_store_close(message_store);

  // chek revocation for remote_as (using aquired witness and stored accumulator)
  // ret = 0 if __not__ revoked (id into accumulator)
  int revoked = pbgp_is_revoked(g_setup, remote_as, g_epoch->accumulator, rcv_witness);
  if (revoked) {
    pbgpd_msg("pbgpd_open_verify :: asnum (%u) is revoked", remote_as);
  }
  else {
    pbgpd_msg("pbgpd_open_verify :: asnum (%u) not revoked", remote_as);
  }

  pbgp_witness_clear(rcv_witness);
  return (verified && !revoked ? 1 : 0);
}

/******** UPDATE ***************************************************************/

struct buf *
pbgpd_update_sign(struct attr *pkt, struct rde_peer *peer, struct rde_aspath *a,
                  struct bgpd_addr *prefix, u_int8_t prefixlen)
{
  struct buf *buf = NULL;
  time_t timestamp = time(NULL) + 1;
  size_t signature_size = 0;

  u_int32_t local_asnum = rde_local_as();

  u_char serialized_signature[MAX_PKTSIZE];
  u_char message[MAX_PKTSIZE];

  size_t message_offset = 0;

  // uses static buffer, don't free
  const char *addr_repr = log_addr(prefix);

  // pkt (attr) is a list of timestamps + asnum + an ibe signature
  // CA signs both cidr and timestamp. AS(s) sign own timestamps + As(dest)
  // and eventually the whole old message (if any) + own AS number

  if (NULL == pkt) {
    pbgpd_msg("pbgpd_update_sign :: originating signature for %s to AS(%d)",
      addr_repr, peer->conf.remote_as);

    cidr_t cidr;
    store_key_t cidr_key = { CIDR, 0, sizeof(cidr), (unsigned char *) &cidr };

    // @postponed make this work with ipv6
    cidr.index = SIGNATURE_INDEX;
    cidr.addr = prefix->v4;
    cidr.bits = prefixlen;

    // we are the only AS that owns CA signature and timestamp on this (originating) prefix
    //  retrieve this CA signature (and timestamp) ON (prefix + netmask + timestamp)
    size_t tbuf_size = 0;
    pbgp_store_uget_size(g_store_envelope, &cidr_key, &signature_size);

    if (signature_size <= 0) {
      // for legacy BGP speaker compatibility we just silently go on without security checks
      pbgpd_msg("pbgpd_update_sign :: cannot find signature for %s, not originating path "
        "(unsecured neighbor)", addr_repr);
      return NULL;
    }
    else if (aspath_count(a->aspath->data, a->aspath->len)) {
      // i'm the IP(l) owner, check that aspath is empty
      fatalx("pbgpd_update_sign :: aspath must be empty when originating signature");
    }

    assert(signature_size > 0);

    // @see pbgp_action_join() for the format of envelope
    unsigned char old_serialized_signature[signature_size];
    pbgp_store_uget(g_store_envelope, &cidr_key, old_serialized_signature, &signature_size);

    // now get the CA signed serialized timestamp
    cidr.index = local_asnum;
    cidr_key.type = MESSAGE;

    pbgp_store_uget_size(g_store_envelope, &cidr_key, &tbuf_size);
    assert(tbuf_size > 0);

    // ca_signed_timestamp = serialized(cidr + timestamp + asnum origin)
    //  we don't need to include cidr as it is sent with the packet
    u_char ca_message_buffer[tbuf_size];

    // we are the only AS that knows the CA timestamp on this cidr (prefix)
    //    so we __must__ append the serialized RIR data to the message to sign
    pbgp_store_uget(g_store_envelope, &cidr_key, ca_message_buffer, &tbuf_size);
    assert(tbuf_size == sizeof(cidr) + sizeof(time_t) + sizeof(local_asnum));

    assert(signature_size < sizeof(serialized_signature));
    assert(tbuf_size < sizeof(message));

    // store [ CIDR, t(0), AS(0) ] inside message buffer
    memcpy(serialized_signature, old_serialized_signature, signature_size);
    memcpy(message, ca_message_buffer, (message_offset += tbuf_size));
  }
  else {
    pbgpd_msg("pbgpd_update_sign :: aggregating on (%s... / %d) (%s) to AS:%d",
      pbgp_rsa_bin2hex(pkt->data, pkt->len > 16 ? 16 : pkt->len), pkt->len, addr_repr, peer->conf.remote_as);

    // size of signed message
    memcpy(&message_offset, pkt->data, sizeof(message_offset));

    memcpy(&signature_size, pkt->data + sizeof(message_offset) + message_offset, sizeof(signature_size));
    assert(signature_size == pkt->len - message_offset - (sizeof(size_t) * 2));

    // extract ibe_signature from pkt
    u_char old_serialized_signature[signature_size];
    memcpy(&old_serialized_signature, pkt->data + message_offset + (sizeof(size_t) * 2), signature_size);

    assert(signature_size < sizeof(serialized_signature));
    assert(message_offset < sizeof(message));

    memcpy(serialized_signature, old_serialized_signature, signature_size);
    memcpy(message, pkt->data + sizeof(size_t), message_offset);
  }

  // compute aggregated signature
  ibe_signature_t *ibe_signature;
  pbgp_ibe_signature_init(g_setup, &ibe_signature);
  pbgp_ibe_signature_unserialize(serialized_signature, ibe_signature);

  // build buffer to sign [ t0, AS0, t1, AS1 ... ASn ]
  size_t to_sign_size = message_offset + sizeof(time_t) + sizeof(peer->conf.remote_as);
  u_char to_sign[to_sign_size];
  memcpy(to_sign, message, message_offset);

  // append local timestamp and remote AS number
  memcpy(to_sign + message_offset, &timestamp, sizeof(time_t));
  memcpy(to_sign + message_offset + sizeof(time_t), &(peer->conf.remote_as), sizeof(peer->conf.remote_as));

  pbgp_debug("pbgp_store_sign :: message for AS(%d) (%s / %d)", peer->conf.remote_as,
    pbgp_rsa_bin2hex(to_sign, sizeof(to_sign)), sizeof(to_sign));

  // sign timestamps
  pbgp_ibe_sign(g_setup, g_ibe_keypair, to_sign, sizeof(to_sign), ibe_signature);

  signature_size = pbgp_ibe_serialized_signature_size(ibe_signature);
  unsigned char new_signature[signature_size];
  pbgp_ibe_signature_serialize(ibe_signature, new_signature);

  pbgp_ibe_signature_clear(ibe_signature);

  // [ SZ1, t(0), AS(0), ... t(n), AS(n), SZ2, new(ibe_signature_size), new(ibe_signature) ]

  size_t total_len = sizeof(to_sign_size) + to_sign_size + sizeof(signature_size) + signature_size;
  buf = buf_open(total_len);
  assert(buf);

  buf_add(buf, &to_sign_size, sizeof(to_sign_size));
  buf_add(buf, &to_sign, to_sign_size);
  buf_add(buf, &signature_size, sizeof(signature_size));
  buf_add(buf, new_signature, signature_size);

  return buf;
}

int
pbgpd_update_verify(struct attr *pkt, struct rde_peer *peer, struct rde_aspath *a,
                    struct bgpd_addr *prefix, u_int8_t prefixlen)
{
#if PBGP_BENCHMARK
  struct timeval start, end;
  static double total = 0;
  gettimeofday(&start, NULL);
#endif

  int verified = 0;

  u_int32_t as[MAX_PKTSIZE / sizeof(u_int32_t)],
            ascount = 0;

  // enough is enough
  size_t signature_size = 0, signed_size = 0;

  // message size
  assert(pkt->len > sizeof(signed_size));
  memcpy(&signed_size, pkt->data, sizeof(signed_size));

  size_t message_size = sizeof(time_t) + sizeof(u_int32_t);
  assert(signed_size >= message_size * 2 + sizeof(cidr_t));

  // if we have speakers that don't talk reBGP then this differs from aspath length
  size_t m_number = (signed_size - sizeof(cidr_t)) / message_size;

  memcpy(&signature_size, pkt->data + sizeof(signed_size) + signed_size, sizeof(signature_size));
  assert(signature_size == pkt->len - (sizeof(size_t) * 2 + signed_size));

  // extract ibe_signature from pkt
  u_char old_serialized_signature[signature_size];
  memcpy(&old_serialized_signature, pkt->data + sizeof(size_t) * 2 + signed_size, signature_size);

  // @todo compare as list inside signed message against aspath

  // @postponed make this work with ipv6
  cidr_t cidr;
  cidr.index = SIGNATURE_INDEX;
  cidr.addr = prefix->v4;
  cidr.bits = prefixlen;

  // compare received cidr with the cidr received into signed message
  if (memcmp(&cidr, pkt->data + sizeof(size_t), sizeof(cidr))) {
    pbgpd_msg("pbgp_update_verify :: cidr != message(cidr)");
    goto cleanup;
  }

  store_key_t key = STORE_KEY_INIT;

  store_t *store_messages = pbgp_store_open(NULL);

  u_int32_t i = 0;
  for (i = 0; i < m_number; i++) {
    assert(pkt->len > message_size * i + sizeof(time_t) + sizeof(u_int32_t) + sizeof(cidr_t));

    unsigned char *data = pkt->data + sizeof(size_t);

    u_int32_t signer_id = (0 == i ? 0 : *((u_int32_t *) ((data + sizeof(cidr_t) + message_size * i - sizeof(u_int32_t)))));

    size_t pktlen = sizeof(cidr_t) + sizeof(time_t) + sizeof(u_int32_t) + message_size * i;
    assert(pktlen < pkt->len);

    pbgp_debug("pbgp_update_verify :: message AS(%d=%d) (%s / %u)",
      i, signer_id, pbgp_rsa_bin2hex(data, pktlen), pktlen);

    pbgp_store_put(store_messages, STORE_KEY_SET_DATA(key, MESSAGE, signer_id), data, pktlen);

    if (i < m_number - 1) {
      //
      // Checks stored IP(l) A-timestamp (+ CA timestamp) against AS(i)-timestamp
      //
      data += sizeof(cidr_t) + (message_size * i) + sizeof(time_t);

      // data points to current AS, timestamp follows
      u_int32_t asnum = (u_int32_t) *((u_int32_t *) (data));
      time_t timestamp = 0, timestamp_ = *((time_t *) (data + sizeof(asnum)));

      as[ascount++] = asnum;

      size_t tsize = sizeof(time_t);
      u_char as_cidr[sizeof(u_int32_t) + sizeof(cidr_t)];

      memcpy(as_cidr, &asnum, sizeof(u_int32_t));
      memcpy(as_cidr + sizeof(u_int32_t), &cidr, sizeof(cidr_t));

      int found = !pbgp_store_uget(g_store_counters, STORE_KEY_SET_DATA(key, MESSAGE, as_cidr), &timestamp, &tsize);
      if (!found) {
        timestamp = 0;
      }
      if (!found || timestamp_ > timestamp) {
        pbgp_debug("pbgpd_update_verify :: timestamp 0x%08x > 0x%08x for AS(%d) (success, storing)", timestamp_, timestamp, asnum);
        pbgp_store_put(g_store_counters, STORE_KEY_SET_DATA(key, MESSAGE, as_cidr), &timestamp_, tsize);
      }
      else if (found && timestamp_ == timestamp) {
        pbgp_debug("pbgpd_update_verify :: timestamp 0x%08x == 0x%08x for AS(%d) (success)", timestamp_, timestamp, asnum);
        // pass, nop
      }
      else {
        pbgpd_msg("pbgpd_update_verify :: timestamp 0x%08x < 0x%08x for AS(%d) (fail)", timestamp_, timestamp, asnum);
        goto cleanup;
      }
    }
  }

  if (_check_aspath(a, as, ascount)) {
    pbgpd_msg("pbgpd_update_verify :: ASPATH in UPDATE packet does not match AS list in signed message.");
    goto cleanup;
  }

  // unserialize signature
  ibe_signature_t *ibe_signature;
  pbgp_ibe_signature_init(g_setup, &ibe_signature);
  pbgp_ibe_signature_unserialize(old_serialized_signature, ibe_signature);

  verified = !pbgp_ibe_verify(g_setup, ibe_signature, store_messages);

  pbgp_store_close(store_messages);
  pbgp_ibe_signature_clear(ibe_signature);

cleanup:

#if PBGP_BENCHMARK
  gettimeofday(&end, NULL);
  double overhead = __timediff(start, end);
  total += overhead;
  pbgpd_msg("overhead after vrfy: %.0f (total=%.0f)", overhead, total);
#endif

  return verified;
}
