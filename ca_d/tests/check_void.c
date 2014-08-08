#include <check.h>
#include <stdlib.h>

#include "check_pbgp.h"

START_TEST(test_check_void)
{
  fail_if(1 != 1, "*UNREACHED*");
}
END_TEST

Suite * make_void_suite(void)
{
  Suite *s = suite_create("void");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_void);
  suite_add_tcase(s, tc_core);
  return s;
}
