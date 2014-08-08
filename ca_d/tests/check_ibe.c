#include <check.h>
#include <stdlib.h>

#include "pbgp.h"
#include "check_pbgp.h"

static inline ibe_signature_t *__sign(u_int32_t signer_id, setup_params_t *setup,
                                store_t *store, ibe_signature_t *signature)
{
  store_key_t key = STORE_KEY_INIT;

  // make message
  char msg[BUFSIZ];
  snprintf(msg, sizeof msg, "msg-%d", signer_id);
  size_t mlen = strlen(msg) + 1;

  // generate ibe keypair for signer_id
  ibe_keypair_t *ibe_keypair = NULL;
  pbgp_ibe_keypair_init(setup, &ibe_keypair);
  pbgp_ibe_keypair_gen(setup, signer_id, ibe_keypair);

//  printf ("keylen:%d %d\n", element_length_in_bytes(ibe_keypair->priv0),
//          element_length_in_bytes(ibe_keypair->priv1));

  // sign message
  pbgp_ibe_sign(setup, ibe_keypair, (const unsigned char *) msg, mlen, signature);

  // store signer_id -> message into list
  pbgp_store_put(store, STORE_KEY_SET_DATA(key, MESSAGE, signer_id), (void *) msg, mlen);

  // cleanup
  pbgp_ibe_keypair_clear(ibe_keypair);
  return signature;
}

START_TEST(test_check_ibe)
{
  int n = 10, signers = 5, i = 0;

  assert(n > signers);

  setup_params_t *setup = pbgp_setup_init(n);
  store_t *store = pbgp_store_open(NULL);

  pbgp_setup_fill(setup);

  u_int32_t ret = 0;

  ibe_signature_t *signature = NULL;
  pbgp_ibe_signature_clear(signature);
  pbgp_ibe_signature_init(setup, &signature);

  for (i = 0; i < signers; i++) {
    signature = __sign(i, setup, store, signature);
  }

  // Success
  ret = pbgp_ibe_verify(setup, signature, store);
  fail_if (ret != 0, "pbgp_ibe_verify (3): fail");

  // Let's change signature, it must fail
  element_random(signature->u);
  ret = pbgp_ibe_verify(setup, signature, store);
  fail_if (ret == 0, "pbgp_ibe_verify (4): fail");

  // test serialize
  unsigned char buf[pbgp_ibe_serialized_signature_size(signature)];
  memset (buf, 0, sizeof buf);
  pbgp_ibe_signature_serialize(signature, buf);

  element_t e;
  element_init_G1(e, setup->pairing);

  element_from_bytes(e, buf);
  fail_if(element_cmp(e, signature->u), "pbgp_ibe_signature_serialize :: error");

  element_from_bytes(e, buf + element_length_in_bytes(signature->u));
  fail_if(element_cmp(e, signature->v), "pbgp_ibe_signature_serialize :: error");

  element_from_bytes(e, buf + element_length_in_bytes(signature->u) + element_length_in_bytes(signature->v));
  fail_if(element_cmp(e, signature->w), "pbgp_ibe_signature_serialize :: error");

//  printf ("signlen:%d %d %d\n",
//          element_length_in_bytes(signature->u), element_length_in_bytes(signature->v), element_length_in_bytes(signature->w));

  // test save and load keypair

  ibe_keypair_t *ibe_keypair = NULL;
  pbgp_ibe_keypair_init(setup, &ibe_keypair);
  pbgp_ibe_keypair_gen(setup, 0, ibe_keypair);
  pbgp_ibe_save_keypair(store, ibe_keypair);

  ibe_keypair_t *ibe_keypair2 = NULL;
  pbgp_ibe_keypair_init(setup, &ibe_keypair2);
  pbgp_ibe_load_keypair(store, ibe_keypair2);

  fail_if (element_cmp(ibe_keypair->priv0, ibe_keypair2->priv0),
           "pbgp_ibe_load_keypair (1) :: error");
  fail_if (element_cmp(ibe_keypair->priv1, ibe_keypair2->priv1),
           "pbgp_ibe_load_keypair (2) :: error");
  fail_if (element_cmp(ibe_keypair->pub0, ibe_keypair2->pub0),
           "pbgp_ibe_load_keypair (3) :: error");
  fail_if (element_cmp(ibe_keypair->pub1, ibe_keypair2->pub1),
           "pbgp_ibe_load_keypair (4) :: error");

  pbgp_ibe_keypair_clear(ibe_keypair);

  ///////////////////// cleanup

  pbgp_ibe_signature_clear(signature);
  pbgp_setup_clear(&setup);
  pbgp_store_close(store);
}
END_TEST

Suite * make_ibe_suite(void)
{
  Suite *s = suite_create("ibe");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_ibe);
  suite_add_tcase(s, tc_core);
  return s;
}
