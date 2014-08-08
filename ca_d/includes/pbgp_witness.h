#ifndef PBGP_WITNESS_H
#define PBGP_WITNESS_H

#include "pbgp_setup.h"
#include "pbgp_store.h"

void pbgp_witness_create(setup_params_t *setup,
               store_t *active, uint32_t id, element_t witness);

void
pbgp_witness_update(setup_params_t *setup,
               store_t *added,
               store_t *revoked,
               uint32_t id, element_t witness);

void
pbgp_witness_clear(element_t witness);

#endif

