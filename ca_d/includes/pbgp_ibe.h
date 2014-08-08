#ifndef PBGP_IBE_H
#define PBGP_IBE_H

typedef struct {
  element_t pub0;
  element_t priv0;
  element_t pub1;
  element_t priv1;
  // uint32_t   id;
} ibe_keypair_t;

typedef struct {
  element_t u;
  element_t v;
  element_t w;
} ibe_signature_t;

void
pbgp_ibe_save_keypair(store_t *store, ibe_keypair_t *keys);

void
pbgp_ibe_load_keypair(store_t *store, ibe_keypair_t *keys);

size_t
pbgp_ibe_serialized_signature_size(ibe_signature_t *signature);

unsigned char *
pbgp_ibe_signature_serialize(ibe_signature_t *signature, unsigned char *buf);

int
pbgp_ibe_signature_unserialize(unsigned char *buf, ibe_signature_t *signature);

void
pbgp_ibe_sign(setup_params_t *setup,
              ibe_keypair_t *key,
              const unsigned char *m,
              size_t mlen, ibe_signature_t *sign);

int
pbgp_ibe_verify(setup_params_t *setup, ibe_signature_t *sign,
              store_t *store);

void
pbgp_ibe_keypair_gen(setup_params_t *setup, uint32_t signer_id, ibe_keypair_t *keys);

void
pbgp_ibe_keypair_init(setup_params_t *setup, ibe_keypair_t **keys);

void
pbgp_ibe_keypair_clear(ibe_keypair_t *keys);

void
pbgp_ibe_signature_init(setup_params_t *setup, ibe_signature_t **sign);

void
pbgp_ibe_signature_clear(ibe_signature_t *s);


#endif

