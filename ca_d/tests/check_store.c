#include <check.h>
#include <stdlib.h>

#include "check_pbgp.h"
#include "pbgp.h"

START_TEST(test_check_store)
{
  store_t *store = pbgp_store_open(NULL);
  fail_if(!store, "pbgp_store_open");

  char *ks = "testkey";
  store_key_t key = { 0, 0, strlen(ks) + 1, (unsigned char *) ks };

  pbgp_store_put(store, &key, "testdata", strlen("testdata") + 1);

  size_t size = 0;

  pbgp_store_uget(store, &key, NULL, &size);
  fail_if (size <= 0);

  char hdata[size];
  pbgp_store_uget(store, &key, hdata, &size);

  // pbgp_debug("data:%s", hdata);
  fail_if(strcmp(hdata, "testdata"), "pbgp_store_uget");

  key.data = (unsigned char *) "testkey2";
  key.dsize = strlen("testkey2") + 1;

  pbgp_store_put(store, &key, "testdata2", strlen("testdata2") + 1);

  key.data = (unsigned char *) "testkey3";
  key.dsize = strlen("testkey3") + 1;

  pbgp_store_put(store, &key, "testdata3", strlen("testdata3") + 1);

  store_iterator_t *iterator = pbgp_store_iterator_open(store);

  while(1)
  {
    size_t ksize = 0, dsize = 0;

    int ret = pbgp_store_iterator_uget_next_size(iterator, &ksize, &dsize);
    if (ret != 0) {
      break ;
    }

    ksize -= STORE_KEY_METADATA_LENGTH;
    fail_if (ksize <= 0);

    unsigned char kbuf[ksize];
    memset (kbuf, 0, ksize);

    key.data = kbuf;
    key.dsize = sizeof(kbuf);

    unsigned char data[dsize];
    memset (data, 0, dsize);

    ret = pbgp_store_iterator_uget_next(iterator, &key, data, &dsize);
    if (ret != 0) {
      break ;
    }
    // pbgp_debug("key:%s data:%s size:%d", key.data, data, dsize);
  }

  pbgp_store_iterator_close(iterator);
  pbgp_store_close(store);
}
END_TEST

Suite * make_store_suite(void)
{
  Suite *s = suite_create("store");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_store);
  suite_add_tcase(s, tc_core);
  return s;
}
