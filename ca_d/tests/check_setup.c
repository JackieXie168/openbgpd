#if HAVE_CONFIG_G
# include "config.h"
#endif

#if HAVE_LIBUUID
# include <uuid/uuid.h>
#endif

#include <check.h>
#include <stdlib.h>

#include "pbgp.h"
#include "check_pbgp.h"

START_TEST(test_check_setup)
{
  int n = 10;
  setup_params_t *setup = pbgp_setup_init(n);
  fail_if(!setup, "pbgp_setup_init");

  store_t *store = pbgp_store_open(NULL);
  fail_if(!store, "pbgp_store_open :: error");

  pbgp_setup_fill(setup);

  // [g, ibePub, z, n, P] + [pk rsa]
  pbgp_setup_save_pubkey(setup, store);

  // [gamma, gammapow_np1] + [sk rsa]
  pbgp_setup_save_privkey(setup, store);

  setup_params_t *setup_load = pbgp_setup_init(n);

  // [g, ibePub, z, n, P] + [pk rsa]
  pbgp_setup_load_pubkey(setup_load, store);

  fail_if (element_cmp(setup_load->g, setup->g));
  fail_if (element_cmp(setup_load->ibePub, setup->ibePub));
  fail_if (element_cmp(setup_load->z, setup->z));
  fail_if (setup_load->n != setup->n);
  fail_if (element_cmp(setup_load->P[0], setup->P[0]));
  fail_if (element_cmp(setup_load->P[setup_load->n], setup->P[setup->n]));

  // [gamma, gammapow_np1] + [sk rsa]
  pbgp_setup_load_privkey(setup_load, store);

  fail_if (element_cmp(setup_load->gamma, setup->gamma));
  fail_if (element_cmp(setup_load->gammapow_np1, setup->gammapow_np1));

  /////////// test random assignment
#if HAVE_LIBUUID
  uuid_t uuid;
  uuid_generate(uuid);
  element_t rnd;
  element_init_G1(rnd, setup->pairing);
  element_from_hash(rnd, uuid, sizeof uuid);
  fail_if (element_is0(rnd));
  element_clear(rnd);
#endif

  pbgp_setup_clear(&setup);
  pbgp_setup_clear(&setup_load);

  pbgp_store_close(store);
}
END_TEST

Suite * make_setup_suite(void)
{
  Suite *s = suite_create("setup");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_setup);
  suite_add_tcase(s, tc_core);
  return s;
}
