#ifndef PBGP_H
#define PBGP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <pbc/pbc.h>
#include <gmp.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>

#ifdef BSD
# include <netinet/in.h>
#endif

#include <arpa/inet.h>
#include <sys/socket.h>

#include "pbgp_store.h"
#include "pbgp_rsa.h"
#include "pbgp_setup.h"
#include "pbgp_witness.h"
#include "pbgp_accumulator.h"
#include "pbgp_ibe.h"
#include "pbgp_epoch.h"
#include "pbgp_actions.h"

#define PBGP_DEBUG

#ifdef PBGP_DEBUG

static __inline__ void pbgp_debug(char * fmt, ...) {
  //  if (errno && errno != EINVAL) {
  //    perror("[!] Last error: ");
  //  }
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[*] ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  fflush(stderr);
}
#else
#define pbgp_debug(fmt...)
#endif

static inline int
_pbgp_fatal(const char *function, unsigned line, const char *fmt, ...) {
  if (errno) {
    perror("[!] Last error: ");
  }
  fprintf(stderr, "[!] Fatal error [%s:%d]: ", function, line);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  exit(EXIT_FAILURE);
  /*UNREACHED*/
  return 0;
}

#define pbgp_fatal(a...) _pbgp_fatal(__FUNCTION__, __LINE__, (a))

#define xmalloc(a) _xmalloc((a), __FUNCTION__, __LINE__)

#define xrealloc(a, b) _xrealloc((a), (b), __FUNCTION__, __LINE__)

static inline void
xfree(void *ptr) {
  if (NULL != ptr) {
    free(ptr);
    ptr = NULL;
  }
}

static inline void *
_xmalloc(size_t size, const char *function, unsigned line) {
  void *temp = malloc(size);
  if (temp == NULL) {
    fprintf(stderr, "[-] Malloc failure [%s:%d]\n", function, line);
    exit(EXIT_FAILURE);
  }
  memset(temp, 0, size);
  return temp;
}

static inline void *
_xrealloc(void *ptr, size_t size, const char *function, unsigned line) {
  void *temp = realloc(ptr, size);
  if (temp == NULL) {
    fprintf(stderr, "[-] Realloc failure [%s:%d]\n", function, line);
    exit(EXIT_FAILURE);
  }
  return temp;
}

#endif

