#ifndef PBGP_EPOCH_H
#define PBGP_EPOCH_H

typedef struct {
  uint32_t value;
  element_t accumulator;

  // store_t *added;
  // store_t *revoked;

  /* RSA signatures */

  unsigned char *signature_added;
  unsigned char *signature_revoked;
  unsigned char *signature_accumulator;

  size_t signature_added_len;
  size_t signature_revoked_len;
  size_t signature_accumulator_len;

} epoch_t;

void
pbgp_epoch_load(store_t *store, epoch_t *epoch, store_t *store_added, store_t *store_revoked);

void
pbgp_epoch_save(store_t *store, epoch_t *epoch, store_t *store_added, store_t *store_revoked);

// void
// pbgp_epoch_update(epoch_t *epoch, setup_params_t *setup, store_t *store_added, store_t *store_revoked);

void
pbgp_epoch_claim_new(setup_params_t *setup,
                     store_t *store_epoch,
                     store_t *store_added,
                     store_t *store_revoked,
                     store_t *store_glb_added,
                     store_t *store_glb_revoked);

void
pbgp_epoch_init(epoch_t **epoch, setup_params_t *setup);

void
pbgp_epoch_clear(epoch_t *epoch);

int
pbgp_is_revoked(setup_params_t *setup, uint32_t id,
                element_t accumulator, element_t witness);

#endif
