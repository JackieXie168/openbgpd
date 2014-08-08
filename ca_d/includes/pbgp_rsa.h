#ifndef PBGP_RSA_H
#define PBGP_RSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

EVP_PKEY *pbgp_rsa_generate(void);

char *
pbgp_rsa_get_sk_pem(EVP_PKEY *pkey);

char *
pbgp_rsa_get_pk_pem(EVP_PKEY *pkey);

EVP_PKEY *
pbgp_rsa_get_sk(const char *pem);

EVP_PKEY *
pbgp_rsa_get_pk(const char *pem);

char *
pbgp_rsa_bin2hex(const unsigned char *in, size_t len);

unsigned int
pbgp_rsa_ubin2hex(const unsigned char *in, size_t ilen, char *out);

///////////////////////////////////////////

unsigned int
pbgp_rsa_hash(const unsigned char *input, unsigned char **md, size_t ilen);

unsigned int
pbgp_rsa_uhash(const unsigned char *input, size_t ilen, unsigned char *md);

unsigned int
pbgp_rsa_uhash_list_keys(store_t *store, unsigned char *md);

unsigned int
pbgp_rsa_uhash_list_data(store_t *store, unsigned char *md);

unsigned int
pbgp_rsa_sign(EVP_PKEY *key, const unsigned char *data, size_t ilen, unsigned char **sig);

unsigned int
pbgp_rsa_usign(EVP_PKEY *key, const unsigned char *data, unsigned int dlen, unsigned char *sig);

int
pbgp_rsa_verify(EVP_PKEY *key, const unsigned char *data, unsigned int dlen, const unsigned char *sig, unsigned int siglen);

#endif

