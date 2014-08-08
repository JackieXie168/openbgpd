#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

static void
_witness_set_product(setup_params_t *setup, store_t *asnums, uint32_t id, element_t result)
{
  uint32_t asnum = 0;

  store_iterator_t *iterator = pbgp_store_iterator_open(asnums);
  store_key_t key = *(STORE_KEY_SET_DATA(key, ASLIST, asnum));

  element_set1(result);

  for (uint32_t i = 0, pos = 0, np1 = setup->n + 1;
    pbgp_store_iterator_uget_next(iterator, &key, NULL, NULL) == 0; i++) {
    if (asnum == id) {
      continue ;
    }
    pos = np1 - asnum + id;
    if (pos >= np1) {
      pos-- ;
    }
    assert (setup->n * 2 - 1 > pos);
    element_mul(result, result, setup->P[pos]);
  }
  pbgp_store_iterator_close(iterator);
}

/**
 * Witness (used for AS list)
 *
 * @param witness     must be uninitialized
 * @asnums            asnum list
 * @param id          integer (id) to add to asnum list
 *
 *  Remember to call element_clear(witness) once used
 */
void
pbgp_witness_create(setup_params_t *setup,
                    store_t *asnums, uint32_t id, element_t witness)
{
  element_init_G1(witness, setup->pairing);
  _witness_set_product(setup, asnums, id, witness);
}

void
pbgp_witness_clear(element_t witness)
{
  element_clear(witness);
}

/**
 *  @param witness gets modified
 */
void
pbgp_witness_update(setup_params_t *setup,
                    store_t *added, store_t *revoked,
                    uint32_t id, element_t witness)
{
  element_t num, den, witt;

  element_init_G1(num, setup->pairing);
  element_init_G1(den, setup->pairing);
  element_init_G1(witt, setup->pairing);

  _witness_set_product(setup, added, id, num);
  _witness_set_product(setup, revoked, id, den);

  // Multiply
  //
  //       g[np1 - j + i] added
  // w *=  ---------------------
  //       g[np1 - j + i] revoked
  //
  //    asnum(s) during last epoch

  element_div(witt, num, den);
  element_mul(witness, witness, witt);

  element_clear(num);
  element_clear(den);
  element_clear(witt);
}