#include <check.h>
#include <stdlib.h>

#include "pbgp.h"
#include "check_pbgp.h"

START_TEST(test_check_rsa)
{
  // SHA_DIGEST_LENGTH
  unsigned char *binary_hash = NULL;
  unsigned int len = pbgp_rsa_hash((unsigned char *) "w00t", &binary_hash, strlen("w00t"));
  char *hash = pbgp_rsa_bin2hex(binary_hash, len);
  // pbgp_debug("HASH (1):%s", hash);
  fail_if (strcmp(hash, "b44384d72cc4b614514dbeee72a03e4bc75e1bae"), "pbgp_rsa_hash");

  unsigned char binary_uhash[EVP_MAX_MD_SIZE + 1];
  memset (binary_uhash, 0, sizeof binary_uhash);
  len = pbgp_rsa_uhash((unsigned char *) "w00t", strlen("w00t"), binary_uhash);
  char *uhash = pbgp_rsa_bin2hex(binary_uhash, len);
  // pbgp_debug("HASH (2):%s", uhash);
  fail_if (strcmp(uhash, "b44384d72cc4b614514dbeee72a03e4bc75e1bae"), "pbgp_rsa_uhash");
  xfree(uhash);

  int n = 2;
  setup_params_t *setup = pbgp_setup_init(n);
  pbgp_setup_fill(setup);

  char *pk = pbgp_rsa_get_pk_pem(setup->rsa_evp);
  char *sk = pbgp_rsa_get_sk_pem(setup->rsa_evp);

  EVP_PKEY *epk = pbgp_rsa_get_pk(pk);
  EVP_PKEY *esk = pbgp_rsa_get_sk(sk);

  unsigned char *sig;
  len = pbgp_rsa_sign(esk, (unsigned char *) hash, strlen(hash), &sig);
  fail_if(pbgp_rsa_verify(epk, (unsigned char *) hash, strlen(hash), sig, len) != 1, "pbgp_rsa_verify (1)");

  hash[strlen(hash) - 1] = 0;
  fail_if(pbgp_rsa_verify(epk, (unsigned char *) hash, strlen(hash), sig, len) == 1, "pbgp_rsa_verify (2)");

  xfree(hash);

  // TEST list sign is list
  uint32_t id;
  store_t *list = pbgp_store_open(NULL);
  store_key_t key = STORE_KEY_INIT;

  id = 1; pbgp_store_put(list, STORE_KEY_SET_DATA(key, ASLIST, id), &id, sizeof(id));
  id = 2; pbgp_store_put(list, STORE_KEY_SET_DATA(key, ASLIST, id), &id, sizeof(id));
  id = 3; pbgp_store_put(list, STORE_KEY_SET_DATA(key, ASLIST, id), &id, sizeof(id));
  id = 4; pbgp_store_put(list, STORE_KEY_SET_DATA(key, ASLIST, id), &id, sizeof(id));

  memset(binary_uhash, 0, sizeof binary_uhash);
  len = pbgp_rsa_uhash_list_keys(list, binary_uhash);
  uhash = pbgp_rsa_bin2hex(binary_uhash, len);
  // pbgp_debug("HASH (3):%s", uhash);
  fail_if (strcmp(uhash, "1456763f890a84558f99afa687c36b9037697848"), "pbgp_rsa_uhash_list");
  xfree(uhash);

  memset(binary_uhash, 0, sizeof binary_uhash);
  len = pbgp_rsa_uhash_list_data(list, binary_uhash);
  uhash = pbgp_rsa_bin2hex(binary_uhash, len);
  // pbgp_debug("HASH (4):%s", uhash);
  fail_if (strcmp(uhash, "1456763f890a84558f99afa687c36b9037697848"), "pbgp_rsa_uhash_list");
  xfree(uhash);

  // cleanup
  pbgp_store_close(list);
  pbgp_setup_clear(&setup);
}
END_TEST

Suite * make_rsa_suite(void)
{
  Suite *s = suite_create("rsa");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_rsa);
  suite_add_tcase(s, tc_core);
  return s;
}
