#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

/**
 *    Reads [accumulator + 3 rsa signatures]
 *
 *    Remeber to call pbgp_epoch_clear in the caller as this (m)allocates memory for epoch items.
 *
 *    @param store_added      output
 *    @param store_revoked    output
 */
void
pbgp_epoch_load(store_t *store, epoch_t *epoch, store_t *store_added, store_t *store_revoked)
{
  store_key_t key = STORE_KEY_INIT;
  store_iterator_t *iterator = pbgp_store_iterator_open(store);

  while (1) {
    size_t ksize = 0, dsize = 0;
    int ret = pbgp_store_iterator_uget_next_size(iterator, &ksize, &dsize);
    if (ret != 0) {
      break ;
    }
    ksize -= STORE_KEY_METADATA_LENGTH;

    unsigned char kbuf[ksize];
    memset (kbuf, 0, ksize);

    key.data = kbuf;
    key.dsize = sizeof(kbuf);

    unsigned char data[dsize];
    memset (data, 0, dsize);

    ret = pbgp_store_iterator_uget_next(iterator, &key, data, &dsize);
    if (ret != 0) {
      break ;
    }

    switch (key.type) {
      case EPOCH_SIGNATURE_ADDED:
        epoch->signature_added_len = dsize;
        epoch->signature_added = xmalloc(dsize);
        memcpy(epoch->signature_added, data, dsize);
        break;
      case EPOCH_SIGNATURE_REVOKED:
        epoch->signature_revoked_len = dsize;
        epoch->signature_revoked = xmalloc(dsize);
        memcpy(epoch->signature_revoked, data, dsize);
        break;
      case EPOCH_SIGNATURE_ACCUMULATOR:
        epoch->signature_accumulator_len = dsize;
        epoch->signature_accumulator = xmalloc(dsize);
        memcpy(epoch->signature_accumulator, data, dsize);
        break;
      case EPOCH_VALUE:
        assert(sizeof(epoch->value) == dsize);
        memcpy(&(epoch->value), data, dsize);
        break;
      case EPOCH_ACCUMULATOR:
        // allocated in epoch_init()
        element_from_bytes(epoch->accumulator, data);
        break;
      case EPOCH_ADDED:
        if (store_added) {
          key.type = 0;
          pbgp_store_put(store_added, &key, NULL, 0);
        }
        else {
          pbgp_store_delete(store, &key);
        }
        break;
      case EPOCH_REVOKED:
        if (store_revoked) {
          key.type = 0;
          pbgp_store_put(store_revoked, &key, NULL, 0);
        }
        else {
          pbgp_store_delete(store, &key);
        }
        break;
      default:
        break;
    }
  }
  pbgp_store_iterator_close(iterator);
}

/**
 *    Writes [accumulator, + 3 rsa signatures]
 */
void
pbgp_epoch_save(store_t *store, epoch_t *epoch, store_t *store_added, store_t *store_revoked)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, EPOCH, EPOCH_ACCUMULATOR), epoch->accumulator);

  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, EPOCH, EPOCH_VALUE), &(epoch->value), sizeof(epoch->value));

  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, EPOCH, EPOCH_SIGNATURE_ADDED), epoch->signature_added,
                 epoch->signature_added_len);

  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, EPOCH, EPOCH_SIGNATURE_REVOKED), epoch->signature_revoked,
                 epoch->signature_revoked_len);

  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, EPOCH, EPOCH_SIGNATURE_ACCUMULATOR), epoch->signature_accumulator,
                 epoch->signature_accumulator_len);
  //
  // Saves list of added and revoked id
  //
  uint32_t asnum = 0;
  store_iterator_t *iterator = NULL;

  for (iterator = pbgp_store_iterator_open(store_added);
    pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0;  ) {
    key.type = EPOCH_ADDED;
    pbgp_store_put(store, &key, NULL, 0);
  }
  pbgp_store_iterator_close(iterator);

  for (iterator = pbgp_store_iterator_open(store_revoked);
    pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0;  ) {
    key.type = EPOCH_REVOKED;
    pbgp_store_put(store, &key, NULL, 0);
  }
  pbgp_store_iterator_close(iterator);
}

static void
_pbgp_epoch_update(setup_params_t *setup, store_t *store_added, store_t *store_revoked, epoch_t *epoch)
{
  unsigned int hsize = 0;
  unsigned char hash[EVP_MAX_MD_SIZE + 1];

  // Update the accumulator (from the old one) - in place update
  pbgp_accumulator_update(setup, store_added, store_revoked, epoch->accumulator);

  // UNREACHED: see https://groups.google.com/d/msg/pbc-devel/I9PvEi52BA4/_9n2eeksKXcJ
  //    element_is0() is always TRUE and equal to element_is1() inside G1
  //
  // if (element_is0(epoch->accumulator)) {
  //   element_set1(epoch->accumulator);
  // }

  // Update epoch number
  epoch->value ++;

  // Clear old signatures
  xfree(epoch->signature_added);
  xfree(epoch->signature_revoked);
  xfree(epoch->signature_accumulator);

  // Sign epoch added list (automatically (m)allocate signature)
  memset (hash, 0, sizeof hash);
  hsize = pbgp_rsa_uhash_list_keys(store_added, hash);
  epoch->signature_added_len = pbgp_rsa_sign(setup->rsa_evp, hash, hsize, &epoch->signature_added);

  // Sign epoch revoked list (automatically (m)allocate signature)
  memset (hash, 0, sizeof hash);
  hsize = pbgp_rsa_uhash_list_keys(store_revoked, hash);
  epoch->signature_revoked_len = pbgp_rsa_sign(setup->rsa_evp, hash, hsize, &epoch->signature_revoked);

  // Get accumulator buffer
  unsigned char accbuf[element_length_in_bytes(epoch->accumulator)];

  memset (accbuf, 0, sizeof (accbuf));
  hsize = element_to_bytes(accbuf, epoch->accumulator);

  // Sign accumulator value (automatically (m)allocate signature)
  epoch->signature_accumulator_len = pbgp_rsa_sign(setup->rsa_evp, accbuf, hsize, &epoch->signature_accumulator);
}

void
pbgp_epoch_claim_new(setup_params_t *setup,
                     store_t *store_epoch,
                     store_t *store_added,
                     store_t *store_revoked,
                     store_t *store_glb_added,
                     store_t *store_glb_revoked)
{
  epoch_t *epoch = NULL;
  pbgp_epoch_init(&epoch, setup);
  //
  // Try loading old epoch (value & accumulator & signatures)
  //   (does nothing if it cannot find epoch items in store)
  //
  pbgp_epoch_load(store_epoch, epoch, NULL, NULL);

  // Update epoch: accumulator, signatures and epoch value
  _pbgp_epoch_update(setup, store_added, store_revoked, epoch);

  // Saves new epoch (update epoch storage)
  pbgp_epoch_save(store_epoch, epoch, store_added, store_revoked);

  // clear saved (stored) epoch from memory
  pbgp_epoch_clear(epoch);

  uint32_t asnum = 0;

  store_iterator_t *iterator = NULL;
  store_key_t key = STORE_KEY_INIT;

  // Update globally added entities
  for (iterator = pbgp_store_iterator_open(store_added);
    pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0; ) {
    pbgp_store_put(store_glb_added, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, 0);
    pbgp_store_delete(store_glb_revoked, STORE_KEY_SET_DATA(key, ASLIST, asnum));
  }
  pbgp_store_iterator_close(iterator);

  // Update globally revoked entities
  for (iterator = pbgp_store_iterator_open(store_revoked);
    pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0; ) {
    pbgp_store_put(store_glb_revoked, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, 0);
    pbgp_store_delete(store_glb_added, STORE_KEY_SET_DATA(key, ASLIST, asnum));
  }
  pbgp_store_iterator_close(iterator);
}

////////////////////////////////////////////////////////////////////////////////
//

/**
 * @return    0 if id is __not__ revoked
 */
int
pbgp_is_revoked(setup_params_t *setup, uint32_t id,
                element_t accumulator, element_t witness)
{
  assert(setup && id < setup->n * 2 - 1);
  element_t num, den, check;

  element_init_GT(num, setup->pairing);
  element_init_GT(den, setup->pairing);
  element_init_GT(check, setup->pairing);

  element_pairing(num, setup->P[id], accumulator);
  element_pairing(den, setup->g, witness);

  element_div(check, num, den);

  int rv = element_cmp(check, setup->z);

  element_clear(num);
  element_clear(den);
  element_clear(check);

  return rv;
}

////////////////////////////////////////////////////////////////////////////////
//

void
pbgp_epoch_init(epoch_t **epoch, setup_params_t *setup)
{
  *epoch = xmalloc(sizeof (epoch_t));
  element_init_G1((*epoch)->accumulator, setup->pairing);
}

void
pbgp_epoch_clear(epoch_t *epoch)
{
  if (epoch) {
    pbgp_accumulator_clear(epoch->accumulator);
    xfree(epoch->signature_added);
    xfree(epoch->signature_revoked);
    xfree(epoch->signature_accumulator);
    xfree(epoch);
  }
}
