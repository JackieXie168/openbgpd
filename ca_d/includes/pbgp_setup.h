#ifndef PBGP_SETUP_H
#define PBGP_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pbc/pbc.h>

/**
 *  qbits 512
 *  rbits 160
 */
#define PBC_PARAM_ASCII "type a\n\
q 2130799500638452803386978008908170942671936217954797752100182286554989042923957126134993508307356893001697\
268787164802468758788563079769036568675005289499\n\
h 2915904363309327134029095883995123508626893311349904719892941691139204447868795297522508553669040190313500\n\
r 730750818665451459101842416358717970580269694977\n\
exp2 159\n\
exp1 59\n\
sign1 1\n\
sign0 1"

typedef struct {
  pairing_t pairing;
  pbc_param_t params;

  element_t g;
  element_t ibePub;
  element_t z;
  element_t *P;
  uint32_t n;

  element_t gamma;
  element_t gammapow_np1;
  //
  // RSA key: contains both public and private params
  //    we split them inside PEM string
  //
  EVP_PKEY *rsa_evp;
} setup_params_t;

setup_params_t *
pbgp_setup_init(uint32_t n);

void
pbgp_setup_pairing(setup_params_t *setup);

void
pbgp_setup_fill(setup_params_t *setup);

void
pbgp_setup_clear(setup_params_t **setup);

void
pbgp_setup_save_pubkey(setup_params_t *setup, store_t *store);

void
pbgp_setup_load_pubkey(setup_params_t *setup, store_t *store);

void
pbgp_setup_save_privkey(setup_params_t *setup, store_t *store);

void
pbgp_setup_load_privkey(setup_params_t *setup, store_t *store);

#endif

