#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

char *
pbgp_generate_envelope_storage_name(uint32_t asnum)
{
  size_t size = snprintf(NULL, 0, ENVELOPE_FILE_FMT, asnum);
  // TODO: check for __C99__ support
  assert(size > 0);
  char *name = xmalloc(size + 1);
  sprintf(name, ENVELOPE_FILE_FMT, asnum);
  return name;
}

/**
 *  Reads [ asnum + witness + RSA_SIGN(env) + ARRAY[ ipv4 + netmask + timestamp + signature ] ]
 *
 *  @param store                     input
 *  @param setup                     input (needed to init witness)
 *
 *  @param asnum                     output
 *  @param witness                   output: must be freed by caller
 *  @param envelope_signature        output: must be freed by caller
 *  @param envelope_signature_size   output
 */
store_t *
pbgp_join_load(setup_params_t *setup,
                 store_t *store,
                 uint32_t *asnum,
                 element_t *witness,
                 unsigned char **envelope_signature,
                 size_t *envelope_signature_size)
{
  assert(asnum && store && witness && setup && envelope_signature && envelope_signature_size);
  store_key_t key = STORE_KEY_INIT;

  size_t size = 0;

  element_init_G1(*witness, setup->pairing);

  size = sizeof(__typeof__(*asnum));
  pbgp_store_uget(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_ASNUM), asnum, &size);

  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_WITNESS), witness);

  pbgp_store_uget_size(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_ENVELOPE_SIGNATURE), envelope_signature_size);

  *envelope_signature = xmalloc(*envelope_signature_size);
  pbgp_store_uget(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_ENVELOPE_SIGNATURE), *envelope_signature, envelope_signature_size);

  return store;
}

/**
 *  Writes [ asnum + witness + RSA_SIGN(env) + ARRAY[ ipv4 + netmask + timestamp + signature ] ]
 */
store_t *
pbgp_join_save(store_t *store,
               uint32_t asnum,
               element_t witness,
               unsigned char *envelope_signature,
               size_t envelope_signature_size)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_ASNUM), &asnum, sizeof asnum);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_WITNESS), witness);
  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, JOIN, JOIN_ENVELOPE_SIGNATURE), envelope_signature, envelope_signature_size);
  return store;
}

////////////////////////////////////////////////////////////////////////////////

/**
 *
 *  Join __one__ AS (with its prefix list) and save signed envelope.
 *
 *    - sign each prefix + netmask entry with CA private ibe key
 *        and store this ibe signature serialized into store_cidr_out output param
 *    - sign the whole prefix list with CA RSA key (should be the whole envelope)
 *    - generate updated witness for this asnum and put it in the envelope
 *    - add input asnum into epoch storage:
 *        will update global list and the accumulator on the next epoch update
 *    - save envelope to permanent storage (to be sent to AS)
 *
 * @param setup               setup params stored and loaded by caller
 * @param ibe_keypair         RIR (CA = ID0) ibe keypair
 * @param asnum               AS=id number of AS to join
 * @param store_cidr_in       input: volatile (in memory) storage for AS prefixes (parsed by caller)
 * @param store_cidr_out      output: permanent storage for signature and prefix list
 * @param store_added         epoch storage of added AS numbers
 * @param store_revoked       epoch storage of revoked AS numbers
 * @param store_glb_added     global storage of added AS numbers
 * @param store_glb_revoked   global storage of revoked AS numbers
 * @return
 *
 *    char *name = __generate_envelope_storage_name(asnum);
 *
 *    store_t *store_cidr_out = pbgp_store_open(name);
 *    if (NULL == store_cidr_out) {
 *      pbgp_debug("pbgp_join_save :: unable to open db (%s)", name);
 *      return NULL;
 *    }
 *
 *  Remember to close stores in the caller
 *    and to call pbgp_ibe_keypair_clear(ibe_keypair)
 *
 */
int
pbgp_action_join(setup_params_t *setup,
                 ibe_keypair_t *ibe_keypair,
                 uint32_t asnum,
                 store_t *store_cidr_in,
                 store_t *store_cidr_out,
                 store_t *store_added,
                 store_t *store_revoked,
                 store_t *store_glb_added,
                 store_t *store_glb_revoked)
{
  store_key_t key = STORE_KEY_INIT;

  // Check that asnum is not already joined (in globally active)
  if (pbgp_store_uget(store_glb_added, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0) {
    pbgp_debug("pbgp_action_join :: asnum already in globally added id");
    return -1 ;
  }

  // Check that asnum is not already revoked (in globally revoked)
  if (pbgp_store_uget(store_glb_revoked, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0) {
    pbgp_debug("pbgp_action_join :: asnum already in globally revoked id");
    return -1 ;
  }

  // Check that asnum is not already joined (in epoch active)
  if (pbgp_store_uget(store_added, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0) {
    pbgp_debug("pbgp_action_join :: asnum already in epoch added id");
    return -1 ;
  }

  // Check that asnum is not already revoked (in epoch revoked)
  if (pbgp_store_uget(store_revoked, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0) {
    pbgp_debug("pbgp_action_join :: asnum already in epoch revoked id");
    return -1 ;
  }

  /* Generate ibe keypair on input(AS = id)
   *    No ! We use RIR (id = 0) ibe keypair generated by caller
   *
   *  ibe_keypair_t *ibe_keypair = NULL;
   *  pbgp_ibe_keypair_init(&ibe_keypair, setup);
   *  pbgp_ibe_keypair_gen(ibe_keypair, setup, asnum);
   */

  //////////////////////////////////////////////////////////////////////////////
  //
  // For each prefix owned by this asnum:
  //
  //      sign prefix + netmask = cidr
  //      save serialized signature
  //      save signer(id) -> message(id)
  //
  cidr_t cidr;
  time_t timestamp = time(NULL);
  store_iterator_t *iterator = pbgp_store_iterator_open(store_cidr_in);
  store_key_t cidr_key = { CIDR, 0, sizeof(cidr), (unsigned char *) &cidr };

  while (pbgp_store_iterator_uget_next(iterator, &cidr_key, NULL, NULL) == 0)
  {
    ibe_signature_t *ibe_signature = NULL;
    pbgp_ibe_signature_init(setup, &ibe_signature);

    // Reserved for signature key
    cidr.index = SIGNATURE_INDEX;
    assert(asnum != SIGNATURE_INDEX);
    //
    // Sign to_sign = serialized form of (prefix + netmask + timestamp + asnum)
    //  Output: ibe_signature
    //
    size_t to_sign_size = sizeof cidr + sizeof timestamp + sizeof asnum;
    unsigned char to_sign[to_sign_size];

    memcpy(to_sign, &cidr, sizeof cidr);
    memcpy(to_sign + sizeof cidr, &timestamp, sizeof timestamp);
    memcpy(to_sign + sizeof cidr + sizeof timestamp, &asnum, sizeof asnum);

    pbgp_ibe_sign(setup, ibe_keypair, to_sign, to_sign_size, ibe_signature);
    //
    // Store [p(j) + netmask(j)]:[SIGNATURE_INDEX] -> SIGNATURE(to_sign)
    //
    size_t cidr_signature_len = pbgp_ibe_serialized_signature_size(ibe_signature);

    unsigned char cidr_signature[cidr_signature_len];
    memset(&cidr_signature, 0, cidr_signature_len);

    pbgp_store_put(store_cidr_out, &cidr_key,
      pbgp_ibe_signature_serialize(ibe_signature, cidr_signature), cidr_signature_len);
    //
    // Store [p(j) + netmask(j)]:[ASNUM] -> [ to_sign = msg = serialized(prefix + netmask + timestamp) ]
    //
    cidr.index = asnum;
    cidr_key.type = MESSAGE;
    pbgp_store_put(store_cidr_out, &cidr_key, to_sign, sizeof to_sign);
    pbgp_ibe_signature_clear(ibe_signature);
  }
  pbgp_store_iterator_close(iterator);

  // Generate the witness for asnum (id)
  element_t witness;
  pbgp_witness_create(setup, store_glb_added, asnum, witness);

  // Generate RSA signature for this envelope [asnum + witness]
  unsigned char envelope_signature[EVP_PKEY_size(setup->rsa_evp)];
  memset(&envelope_signature, 0, sizeof envelope_signature);

  unsigned char buf[sizeof asnum + element_length_in_bytes(witness)];
  memcpy(buf, &asnum, sizeof asnum);
  element_to_bytes(buf + sizeof asnum, witness);

  size_t ssize = pbgp_rsa_usign(setup->rsa_evp, buf, sizeof buf, envelope_signature);

  // Dump the envelope to send to AS
  pbgp_join_save(store_cidr_out, asnum, witness, envelope_signature, ssize);

  element_clear(witness);

  // Update epoch storage (glb storage will be updated during the next epoch update)
  pbgp_store_put(store_added, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, 0);

  /*  No ! We don't generate this, it's up to the caller to clear it.
   *
   *    pbgp_ibe_keypair_clear(ibe_keypair);
   */
  return 0;
}

/**
 *  Update epoch revoked list of AS(id)
 *
 * @param store_added      epoch added asnum / id
 * @param store_revoked    epoch revoked asnum / id
 * @return                 -1 on error, 0 on success
 */
int
pbgp_action_revoke(uint32_t asnum,
                   store_t *store_added,
                   store_t *store_revoked,
                   store_t *store_glb_added)
{
  store_key_t key = { ASLIST, 0, sizeof(asnum), (unsigned char *) &asnum };

  // Check that asnum has joined beforewards (in globally active)
  if (pbgp_store_uget(store_glb_added, &key, NULL, NULL) != 0) {
    pbgp_debug("pbgp_action_revoke :: asnum is not in globally added id");
    return -1 ;
  }

  // Search id into epoch added records
  //    (cannot add and revoke during the same epoch)
  if (pbgp_store_uget(store_added, &key, NULL, NULL) == 0) {
    pbgp_debug("pbgp_action_revoke :: asnum already in epoch added id");
    return -1 ;
  }

  // Add id to epoch revoked records (storage)
  //  we don't remove it from glb added (neither add it to revoked glb)
  //  as the id=asnum will be removed from glb during the next epoch update
  pbgp_store_put(store_revoked, &key, NULL, 0);
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//

/**
 *  Parse network ipv4 address/mask list
 *    ie. comma separated values like "123.122.121.1/24,123.122.122.1,123.122.122.1/16"
 *
 *  This function silently fails on malformed input
 *
 *  @return number of correctly parsed entries
 */
int
pbgp_parse_cidr(const char *input,
                void (*callback)(struct in_addr *, int, void *),
                void *callback_args)
{
  int netmask = 0,
      ret = 0;

  struct in_addr addr;

  char *token = NULL, *ptr, *sep = ",",
       *in = strdup(input);

  assert(input && callback && in);

  if ((token = strtok_r(in, sep, &ptr))) {
    do {
      memset(&addr, 0, sizeof (addr));
      if (strrchr(token, '/') != NULL) {
        netmask = inet_net_pton(AF_INET, token, &addr, sizeof (addr));
        if (netmask == -1) {
          continue ;
        }
      }
      else {
        if (inet_pton(AF_INET, token, &addr) != 1) {
          continue ;
        }
        netmask = sizeof(addr) * 8;
      }
      callback(&addr, netmask, callback_args);
      ret ++;
    }
    while ((token = strtok_r(NULL, sep, &ptr)));
  }

  xfree(in);
  return ret;
}

/**
 * Use this as a callback for pbgp_parse_cidr() to print ascii addresses / netmasks.
 * @see pbgp_parse_cidr
 */
void
pbgp_print_cidr(const struct in_addr *addr, int netmask, void *callback_args)
{
  (void) callback_args ;
  char as[INET_ADDRSTRLEN + 1];
  memset (&as, 0, sizeof as);
  inet_net_ntop(AF_INET, (void *) addr, netmask, as, sizeof(as));
  printf("addr:%s netmask: %d\n", as, netmask);
}

typedef struct
{
  store_t *store;
  uint32_t asnum;
} __cidr_callback_t;

static inline void
__cidr_callback(struct in_addr *addr, int bits, void *args)
{
  // we need to zero out unused address bytes
  u_int32_t mask = 0xffffffff << (32 - bits);
  addr->s_addr &= htonl(mask);
  cidr_t cidr = {*addr, bits, ((__cidr_callback_t *) args)->asnum};
  store_key_t cidr_key = { CIDR, 0, sizeof (cidr), (unsigned char *) &cidr };
  pbgp_store_put(((__cidr_callback_t *) args)->store, &cidr_key, NULL, 0);
}

/**
 * Store parsed prefix list (asnum -> address + netmask) into storage.
 *
 * @param store_cidr_in     output in memory storage / database
 * @return                  number of stored cidr
 */
int
pbgp_store_parsed_cidr(uint32_t asnum, const char *pfxlist, store_t *store_cidr_in)
{
  assert(pfxlist && store_cidr_in);
  __cidr_callback_t callback_args = {store_cidr_in, asnum};
  return pbgp_parse_cidr(pfxlist, __cidr_callback, (void *) &callback_args);
}
