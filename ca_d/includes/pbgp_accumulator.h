#ifndef PBGP_ACCUMULATOR_H
#define PBGP_ACCUMULATOR_H

void pbgp_accumulator_create(setup_params_t *setup, element_t accumulator);

void pbgp_accumulator_update(setup_params_t *setup,
                        store_t *added, store_t *revoked, element_t accumulator);

void
pbgp_accumulator_clear(element_t accumulator);

#endif


