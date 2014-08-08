#ifndef PBGP_ACTIONS_H
#define PBGP_ACTIONS_H

#define SIGNATURE_INDEX     0xffffff
#define ENVELOPE_FILE_FMT   "AS-%u.env"

/**
 *  index   As number (id) or SIGNATURE_INDEX (0xffffff)
 *          inside storage
 */
typedef struct {
  struct in_addr addr;
  int bits;
  uint32_t index;
} cidr_t;

char *
pbgp_generate_envelope_storage_name(uint32_t asnum);

store_t *
pbgp_join_load(setup_params_t *setup,
                 store_t *store,
                 uint32_t *asnum,
                 element_t *witness,
                 unsigned char **envelope_signature,
                 size_t *envelope_signature_size);

store_t *
pbgp_join_save(store_t *store,
               uint32_t asnum,
               element_t witness,
               unsigned char *envelope_signature,
               size_t envelope_signature_size);

int
pbgp_action_join(setup_params_t *setup,
                 ibe_keypair_t *ibe_keypair,
                 uint32_t asnum,
                 store_t *store_cidr_in,
                 store_t *store_cidr_out,
                 store_t *store_added,
                 store_t *store_revoked,
                 store_t *store_glb_added,
                 store_t *store_glb_revoked);

int
pbgp_action_revoke(uint32_t asnum,
                   store_t *store_added,
                   store_t *store_revoked,
                   store_t *store_glb_added);

int
pbgp_parse_cidr(const char *input,
                void (*callback)(struct in_addr *, int, void *),
                void *callback_args);

void
pbgp_print_cidr(const struct in_addr *addr, int netmask, void *callback_args);

int
pbgp_store_parsed_cidr(uint32_t asnum, const char *pfxlist, store_t *store_cidr_in);

#endif

