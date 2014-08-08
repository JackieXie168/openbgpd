#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

static void
_accumulator_set_product(setup_params_t *setup, store_t *asnums, element_t result)
{
  uint32_t asnum = 0;

  store_iterator_t *iterator = pbgp_store_iterator_open(asnums);
  store_key_t key = *(STORE_KEY_SET_DATA(key, ASLIST, asnum));

  element_set1(result);

  for (uint32_t i = 0, pos = 0, np1 = setup->n + 1;
    pbgp_store_iterator_uget_next(iterator, &key, NULL, NULL) == 0; i++) {
    pos = np1 - asnum;
    if (pos == np1) {
      // gammapow_np1 is private for asnum = 0 = CA
      element_mul(result, result, setup->gammapow_np1);
    }
    else {
      if (pos > np1) {
        pos-- ;
      }
      assert (setup->n * 2 - 1 > pos);
      element_mul(result, result, setup->P[pos]);
    }
  }
  pbgp_store_iterator_close(iterator);
}

/**
 * Accumulator
 *
 * @param accumulator   must be uninitialized
 *
 *  Remember to call element_clear(accumulator) once used
 */
void
pbgp_accumulator_create(setup_params_t *setup, element_t accumulator)
{
  element_init_G1(accumulator, setup->pairing);
  element_set1(accumulator);
}

void
pbgp_accumulator_clear(element_t accumulator)
{
  element_clear(accumulator);
}

void
pbgp_accumulator_update(setup_params_t *setup,
                        store_t *added, store_t *revoked, element_t accumulator)
{
  element_t num, den, acct;

  element_init_G1(num, setup->pairing);
  element_init_G1(den, setup->pairing);
  element_init_G1(acct, setup->pairing);

  //
  //  Multiply for each AS
  //
  //    like witness without considering a new id
  //

  _accumulator_set_product(setup, added, num);
  _accumulator_set_product(setup, revoked, den);

  element_div(acct, num, den);
  element_mul(accumulator, accumulator, acct);

  element_clear(num);
  element_clear(den);
  element_clear(acct);
}
