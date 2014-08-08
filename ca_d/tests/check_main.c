#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#if 0
#  include <execinfo.h>
#endif
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

#include "check_pbgp.h"

extern const char *__progname;

void _handler(int sig, struct sigcontext ctx)
{
#if 0
  void *trace[16];
  char **messages = (char **) NULL;
  int i, trace_size = 0;

  printf("[bt] got signal %d\n", sig);

  trace_size = backtrace(trace, 16);

  trace[1] = (void *) ctx.eip;
  messages = backtrace_symbols(trace, trace_size);

  for (i = 1; i < trace_size; ++i) {
    printf("\t[bt] #%d %s\n", i, messages[i]);

    char syscom[256];
    sprintf(syscom, "echo \"\t[bt]\t\" $( addr2line %p -e `cat /proc/%d/cmdline` )",
            trace[i], getpid());

    int ret = system(syscom);
    (void) ret;
  }
#endif
  exit(EXIT_FAILURE);
}

int main(void)
{
  int n;
  SRunner *sr;

  struct sigaction sa;

  sa.sa_handler = (void *) _handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  // sigaction(SIGABRT, &sa, NULL);
  // sigaction(SIGSEGV, &sa, NULL);

  sigaction(SIGUSR1, &sa, NULL);

  sr = srunner_create(make_void_suite());

#if 1
  srunner_add_suite(sr, make_setup_suite());
  srunner_add_suite(sr, make_store_suite());
  srunner_add_suite(sr, make_rsa_suite());
  srunner_add_suite(sr, make_ibe_suite());
  srunner_add_suite(sr, make_accwitt_suite());
  srunner_add_suite(sr, make_epoch_suite());
#endif

  srunner_run_all(sr, CK_VERBOSE);

  n = srunner_ntests_failed(sr);
  srunner_free(sr);

  int ret = system("rm __db* 2> /dev/null");
  (void) ret;

  return (n == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
