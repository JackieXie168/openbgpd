#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_LIBUUID || HAVE_LIBE2FS_UUID
# include <uuid/uuid.h>
#endif

#include "pbgp.h"

/**
 *  Memoized version of element_from_hash
 *    for performance reason
 */
static inline void
_element_from_hash(element_t e, void *data, int len)
{
  // @fixme: store is "left open" when executable close
  static store_t *store = NULL;
  if (!store) {
    store = pbgp_store_open(NULL);
  }
  store_key_t key = { 0, 0, len, (unsigned char *) data };

  size_t size = 0;
  int ret = 0;

  if (0 == pbgp_store_uget_size(store, &key, &size)) {
    unsigned char buf[size];
    memset (buf, 0, size);
    pbgp_store_uget(store, &key, buf, &size);
    ret = element_from_bytes(e, buf);
  }

  if (0 == ret) {
    element_from_hash(e, data, len);
    unsigned char edata[element_length_in_bytes(e)];
    element_to_bytes(edata, e);
    pbgp_store_put(store, &key, edata, sizeof(edata));
  }
}

static inline void
_ibe_get_id_pair(uint32_t asnum, char *id0, size_t id0_len, char *id1, size_t id1_len)
{
  snprintf(id0, id0_len, "%u0", asnum);
  snprintf(id1, id1_len, "%u1", asnum);
}

void
pbgp_ibe_save_keypair(store_t *store, ibe_keypair_t *keys)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PRIV0), keys->priv0);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PRIV1), keys->priv1);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PUB0), keys->pub0);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PUB1), keys->pub1);
}

void
pbgp_ibe_load_keypair(store_t *store, ibe_keypair_t *keys)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PRIV0), &keys->priv0);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PRIV1), &keys->priv1);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PUB0), &keys->pub0);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, IBE, IBE_PUB1), &keys->pub1);
}

size_t
pbgp_ibe_serialized_signature_size(ibe_signature_t *signature)
{
  return (size_t) element_length_in_bytes(signature->u) +
         element_length_in_bytes(signature->w) +
         element_length_in_bytes(signature->v);
}

/**
 * @param buf     must be allocated by caller
 *                pbgp_ibe_serialized_signature_size() bytes long
 */
unsigned char *
pbgp_ibe_signature_serialize(ibe_signature_t *signature, unsigned char *buf)
{
  // Ugly as we recalculate size but still faster than malloc
  int u_len = element_length_in_bytes(signature->u),
      v_len = element_length_in_bytes(signature->v);
  element_to_bytes(buf, signature->u);
  element_to_bytes(buf + u_len, signature->v);
  element_to_bytes(buf + u_len + v_len, signature->w);
  return buf;
}

int
pbgp_ibe_signature_unserialize(unsigned char *buf, ibe_signature_t *signature)
{
  int len = 0;
  len += element_from_bytes(signature->u, buf + len);
  len += element_from_bytes(signature->v, buf + len);
  len += element_from_bytes(signature->w, buf + len);
  return len;
}

/**
 *  In this scheme every signer can aggregate a signature on a different message.
 *
 * @param sign        the computated signature (param modified)
 * @param m           the message to sign
 * @param mlen        message length
 *
 * The __caller__ SHOULD add id:message to some storage as we need the aggregate signature
 *  signers id=asnum to vrfy @see pbgp_ibe_vrfy()
 *
 *    ie. pbgp_store_uput(store, STORE_KEY_SET_DATA(key, ASLIST, signer_id), (void *) m, mlen)
 *
 */
void
pbgp_ibe_sign(setup_params_t *setup,
              ibe_keypair_t *key,
              const unsigned char *m,
              size_t mlen,
              ibe_signature_t *sign)
{
  element_t ri, t1, t2, t3, t4, ci;
  //
  //  Check if this is the first signature
  //    "w must be an unique unseen value"
  //
  if (element_is0(sign->w)) {
#if HAVE_LIBUUID || HAVE_LIBE2FS_UUID
    uuid_t uuid;
    uuid_generate(uuid);
    element_from_hash(sign->w, uuid, sizeof uuid);
#else
    element_random(sign->w);
#endif
    if (element_is0(sign->w)) {
      pbgp_fatal("pbgp_ibe_sign :: random");
    }
  }

  element_init_G1(t1, setup->pairing);
  element_init_G1(t2, setup->pairing);
  element_init_G1(t3, setup->pairing);
  element_init_G1(t4, setup->pairing);

  element_init_Zr(ri, setup->pairing);
  element_init_Zr(ci, setup->pairing);

  // ci = binary_hash(message)

  unsigned char hash[EVP_MAX_MD_SIZE + 1];
  memset(hash, 0, sizeof (hash));

  unsigned int len = pbgp_rsa_uhash(m, mlen, hash);
  element_from_hash(ci, hash, len);

  // ri = random element
  element_random(ri);

  // ri * Pw
  element_mul_zn(t1, sign->w, ri);

  // Pi,0 = key->priv0
  // Pi,1 = key->priv1

  // ci * Pi,1
  element_mul_zn(t2, key->priv1, ci);

  // ri * Pi,0
  // element_mul(t5, ri, key->pub0);

  // ri * Pw + ci * sP(i,1) + sP(i,0)

  element_add(t3, t1, t2);

  // Si = ri * Pw + ci * Pi,1 + Pi,0
  element_add(t3, t3, key->priv0);

  // Ti = ri * P
  element_mul_zn(t4, setup->g, ri);

  // Sum(sign) for each signature
  // w is the same for all signers

  // u = sum(Si)
  element_add(sign->u, sign->u, t3);

  // v = sum(Ti)
  element_add(sign->v, sign->v, t4);

  element_clear(t1);
  element_clear(t2);
  element_clear(t3);
  element_clear(t4);
  element_clear(ri);
  element_clear(ci);
}

/**
 * In this scheme every signer can aggregate a signature on a different message.
 *
 *  This __cannot__ verify multiple messages from the same AS.
 *
 *    We have __one__ signer -> __one__ message but as the message could be the same
 *    for every signer, we can aggregate on it.
 *
 * @param store here we insert all the messages and all the signers
 *        (as we __must__ verify every message of every signer)
 *
 * @return 0 if verify = success.
 *
 */
int
pbgp_ibe_verify(setup_params_t *setup, ibe_signature_t *sign, store_t *store)
{
  assert(sign && setup && store);

  element_t sumID, sumCi, sumTot, Pubi0,
    Pubi1, Pm, t1, p1, p2, e1, e2, ci;

  pairing_pp_t pp1, pp2, pp3;

  element_init_G1(sumID, setup->pairing);
  element_init_G1(sumCi, setup->pairing);
  element_init_G1(sumTot, setup->pairing);
  element_init_G1(Pubi0, setup->pairing);
  element_init_G1(Pubi1, setup->pairing);
  element_init_G1(Pm, setup->pairing);
  element_init_G1(t1, setup->pairing);
  element_init_GT(p1, setup->pairing);
  element_init_GT(p2, setup->pairing);
  element_init_GT(e1, setup->pairing);
  element_init_GT(e2, setup->pairing);

  element_init_Zr(ci, setup->pairing);

  element_set0(sumID);
  element_set0(sumCi);
  //
  //  For each ASNUM in the list
  //
  store_iterator_t *iterator = pbgp_store_iterator_open(store);
  store_key_t key = STORE_KEY_INIT;

  while (1)
  {
    uint32_t id = 0;
    size_t ksize = 0, dsize = 0;

    // This mess is to avoid __any__ malloc call >:/
    int ret = pbgp_store_iterator_uget_next_size(iterator, &ksize, &dsize);
    if (ret != 0) {
      break ;
    }

    // compute key data size
    ksize -= STORE_KEY_METADATA_LENGTH;

    if (sizeof(id) != ksize) {
      continue ;
    }

    // key buffer
    unsigned char kbuf[ksize];
    memset (kbuf, 0, ksize);

    key.data = kbuf;
    key.dsize = sizeof(kbuf);

    // data buffer
    unsigned char message[dsize];
    memset (message, 0, dsize);

    // get asnum + message
    ret = pbgp_store_iterator_uget_next(iterator, &key, message, &dsize);
    if (ret != 0) {
      break ;
    }

    char id0[BUFSIZ],
         id1[BUFSIZ];

    memcpy(&id, kbuf, sizeof id);

    _ibe_get_id_pair(id, id0, sizeof (id0), id1, sizeof (id1));
    //
    // Computes public keys for this AS from its identity
    //
    unsigned char hash[EVP_MAX_MD_SIZE + 1];

    // hash(id0)
    memset(hash, 0, sizeof (hash));
    _element_from_hash(Pubi0, hash, pbgp_rsa_uhash((unsigned char *) id0, strlen(id0), hash));

    // hash(id1)
    memset(hash, 0, sizeof (hash));
    _element_from_hash(Pubi1, hash, pbgp_rsa_uhash((unsigned char *) id1, strlen(id1), hash));

    // ci = hash(m)
    memset(hash, 0, sizeof (hash));
    element_from_hash(ci, hash, pbgp_rsa_uhash(message, dsize, hash));

    // Computes sum(Pi_0) sum(ci * Pi_1)
    element_mul_zn(t1, Pubi1, ci);
    element_add(sumID, sumID, Pubi0);
    element_add(sumCi, sumCi, t1);
  }
  pbgp_store_iterator_close(iterator);

  element_add(sumTot, sumID, sumCi);

  pairing_pp_init(pp1, sumTot, setup->pairing);
  pairing_pp_init(pp2, sign->v, setup->pairing);
  pairing_pp_init(pp3, sign->u, setup->pairing);

  // e(Q = ibePub, sumTot)
  pairing_pp_apply(p1, setup->ibePub, pp1);

  // e(Tn = v, Pw)
  pairing_pp_apply(p2, sign->w, pp2);

  // e(Q = ibePub, sumTot) * e(Tn = v, Pw)
  element_mul(e2, p1, p2);

  // e(Sn = u, P)
  pairing_pp_apply(e1, setup->g, pp3);

  int rv = element_cmp(e1, e2);

  pairing_pp_clear(pp1);
  pairing_pp_clear(pp2);
  pairing_pp_clear(pp3);

  element_clear(sumID);
  element_clear(sumCi);
  element_clear(sumTot);
  element_clear(t1);
  element_clear(ci);
  element_clear(Pubi0);
  element_clear(Pubi1);
  element_clear(Pm);
  element_clear(p1);
  element_clear(p2);
  element_clear(e1);
  element_clear(e2);

  return rv;
}

/**
 * @param keys  must be allocated
 *
 * @see pbgp_ibe_keypair_init
 */
void
pbgp_ibe_keypair_gen(setup_params_t *setup, uint32_t signer_id, ibe_keypair_t *keys)
{
  assert(keys && setup);

  unsigned char hash[EVP_MAX_MD_SIZE + 1];

  char id0[BUFSIZ],
       id1[BUFSIZ];

  _ibe_get_id_pair(signer_id, id0, sizeof (id0), id1, sizeof (id1));
  //
  // generate public id (key) = identity
  // keys->pub0 = hash (id0)
  //
  memset(hash, 0, sizeof (hash));
  element_from_hash(keys->pub0, hash, pbgp_rsa_uhash((unsigned char *) id0, strlen(id0), hash));
  //
  // generate private key from public id
  // priv0 = pub0 * gamma
  // with gamma = secret key CA = s
  //
  element_mul_zn(keys->priv0, keys->pub0, setup->gamma);
  //
  // same goes for id1
  //
  memset(hash, 0, sizeof (hash));
  element_from_hash(keys->pub1, hash, pbgp_rsa_uhash((unsigned char *) id1, strlen(id1), hash));
  //
  // generate private key from public id
  //
  element_mul_zn(keys->priv1, keys->pub1, setup->gamma);
}

////////////////////////////////////////////////////////////////////////////////
//
//  Init / Clear

void
pbgp_ibe_keypair_init(setup_params_t *setup, ibe_keypair_t **keys)
{
  assert(setup);
  *keys = xmalloc(sizeof (ibe_keypair_t));
  element_init_G1((*keys)->pub0, setup->pairing);
  element_init_G1((*keys)->priv0, setup->pairing);
  element_init_G1((*keys)->pub1, setup->pairing);
  element_init_G1((*keys)->priv1, setup->pairing);
}

void
pbgp_ibe_keypair_clear(ibe_keypair_t *keys)
{
  if (keys) {
    element_clear(keys->pub0);
    element_clear(keys->priv0);
    element_clear(keys->pub1);
    element_clear(keys->priv1);
    xfree(keys);
  }
}

void
pbgp_ibe_signature_init(setup_params_t *setup, ibe_signature_t **sign)
{
  assert(setup);
  *sign = xmalloc(sizeof (ibe_signature_t));
  element_init_G1((*sign)->u, setup->pairing);
  element_init_G1((*sign)->v, setup->pairing);
  element_init_G1((*sign)->w, setup->pairing);
  element_set0((*sign)->u);
  element_set0((*sign)->v);
  element_set0((*sign)->w);
}

void
pbgp_ibe_signature_clear(ibe_signature_t *s)
{
  if (s) {
    element_clear(s->u);
    element_clear(s->v);
    element_clear(s->w);
    xfree(s);
  }
}
