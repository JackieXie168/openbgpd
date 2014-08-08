#include <check.h>
#include <stdlib.h>

#include "pbgp.h"
#include "check_pbgp.h"

START_TEST(test_check_accwitt)
{
  u_int32_t signer_id;
  store_key_t key = STORE_KEY_INIT;

  int n = 30, revoked = -1;
  setup_params_t *setup = pbgp_setup_init(n);

  element_t witness, accumulator;

  store_t *act = pbgp_store_open(NULL),
          *add = pbgp_store_open(NULL),
          *rvk = pbgp_store_open(NULL),
          *emp = pbgp_store_open(NULL);

  pbgp_setup_fill(setup);

  pbgp_accumulator_create(setup, accumulator);

  uint32_t wit_signer_id = 10;

  // put some asnums into our list of active asnum
  for (signer_id = 1; signer_id < wit_signer_id; signer_id++) {
    pbgp_store_put(act, STORE_KEY_SET_DATA(key, ASLIST, signer_id), NULL, 0);
  }

  pbgp_accumulator_update(setup, act, rvk, accumulator);
  // element_printf("accumulator (1): %B\n", accumulator);

  // put witness signer_id into added list
  pbgp_store_put(add, STORE_KEY_SET_DATA(key, ASLIST, wit_signer_id), NULL, 0);

  pbgp_witness_create(setup, act, wit_signer_id, witness);

  pbgp_witness_update(setup, add, emp, wit_signer_id, witness);
  pbgp_accumulator_update(setup, add, emp, accumulator);
  revoked = pbgp_is_revoked(setup, wit_signer_id, accumulator, witness);
  fail_if (revoked != 0, "pbgp_is_revoked:: must return NO");

  // put witness id into our list of revoked asnum
  pbgp_store_put(rvk, STORE_KEY_SET_DATA(key, ASLIST, wit_signer_id), NULL, 0);

  pbgp_witness_update(setup, emp, rvk, wit_signer_id, witness);
  pbgp_accumulator_update(setup, emp, rvk, accumulator);
  revoked = pbgp_is_revoked(setup, wit_signer_id, accumulator, witness);
  fail_if (revoked == 0, "pbgp_is_revoked:: must return YES");

  // put witness id into our list of added asnum (again)
  pbgp_store_put(add, STORE_KEY_SET_DATA(key, ASLIST, wit_signer_id), NULL, 0);

  pbgp_witness_update(setup, add, emp, wit_signer_id, witness);
  pbgp_accumulator_update(setup, add, emp, accumulator);
  revoked = pbgp_is_revoked(setup, wit_signer_id, accumulator, witness);
  fail_if (revoked != 0, "pbgp_is_revoked:: must return NO");

  pbgp_accumulator_clear(accumulator);
  pbgp_witness_clear(witness);

  pbgp_setup_clear(&setup);

  pbgp_store_close(act);
  pbgp_store_close(add);
  pbgp_store_close(rvk);
  pbgp_store_close(emp);
}
END_TEST

Suite * make_accwitt_suite(void)
{
  Suite *s = suite_create("accwitt");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_accwitt);
  suite_add_tcase(s, tc_core);
  return s;
}
