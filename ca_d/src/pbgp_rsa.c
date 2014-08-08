#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

#define DEFAULT_DIGEST "SHA1"
#define DEFAULT_CIPHER "RSA"


/**
 * RSA KEYPAIR GENERATION
 */
EVP_PKEY *pbgp_rsa_generate()
{
  EVP_PKEY *pkey = EVP_PKEY_new();
  /*
   *  Fails if /dev/urandom does not exists
   */
  if (RAND_status() != 1) {
    pbgp_fatal("RAND_status");
  }

  BIGNUM *e = BN_new();
  if (!e) {
    pbgp_fatal("BN_new");
  }
  BN_set_word(e, RSA_F4);

  RSA *rsa = RSA_new();
  if (!rsa) {
    pbgp_fatal("RSA_new");
  }

  if (RSA_generate_key_ex(rsa, 1024, e, NULL) != 1) {
    pbgp_fatal("RSA_generate_key");
  }
  BN_free(e);

  if (RSA_check_key(rsa) != 1) {
    pbgp_fatal("RSA_check_key");
  }

  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    pbgp_fatal("EVP_PKEY_set1_RSA");
  }
  return pkey;
}

////////////////////////////////////////////////////////////////////////////////

/**
 *  Read secret key, output ascii pem
 */
char *
pbgp_rsa_get_sk_pem(EVP_PKEY *pkey)
{
  BIO *out = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
  BUF_MEM *buf = NULL;
  BIO_get_mem_ptr(out, &buf);
  buf->data[buf->length - 1] = 0;
  char *sk = strdup(buf->data);
  BIO_free(out);
  return sk;
}

/**
 *  Read public key, output ascii pem
 */
char *
pbgp_rsa_get_pk_pem(EVP_PKEY *pkey)
{
  BIO *out = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(out, pkey);
  BUF_MEM *buf = NULL;
  BIO_get_mem_ptr(out, &buf);
  buf->data[buf->length - 1] = 0;
  char *pk = strdup(buf->data);
  BIO_free(out);
  return pk;
}

/**
 *  Read ascii pem, output rsa secret key
 */
EVP_PKEY *
pbgp_rsa_get_sk(const char *pem)
{
  BIO *in = BIO_new(BIO_s_mem());
  BIO_puts(in, pem);
  EVP_PKEY *esk = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
  BIO_free(in);
  return esk;
}

/**
 *  Read ascii pem, output rsa public key
 */
EVP_PKEY *
pbgp_rsa_get_pk(const char *pem)
{
  BIO *in = BIO_new(BIO_s_mem());
  BIO_puts(in, pem);
  EVP_PKEY *epk = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
  BIO_free(in);
  return epk;
}

////////////////////////////////////////////////////////////////////////////////

static EVP_MD_CTX    _ctx;
static const EVP_MD *_type = NULL;

/**
 *  Must be called manually whithout gcc support
 */
__attribute__((constructor)) static
void _pbgp_rsa_init()
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();
  EVP_MD_CTX_init(&_ctx);
  _type = EVP_get_digestbyname(DEFAULT_DIGEST);
}

/**
 *  Must be called manually whithout gcc support
 */
__attribute__((destructor)) static
void _pbgp_rsa_clear()
{
  EVP_MD_CTX_cleanup(&_ctx);
  EVP_cleanup();
}

////////////////////////////////////////////////////////////////////////////////

char *
pbgp_rsa_bin2hex(const unsigned char *in, size_t len)
{
  char *out = xmalloc(len * 2 + 1);
  for (size_t i = 0; i < len; i++) {
    sprintf(out + i * 2, "%02x", in[i]);
  }
  return out;
}

/**
 *  Same as pbgp_rsa_bin2hex, but memory must be allocate by caller
 *
 * @param out   (ilen = len(in)) * 2 + 1 bytes allocate by caller
 * @return      output length in bytes
 */
unsigned int
pbgp_rsa_ubin2hex(const unsigned char *in, size_t ilen, char *out)
{
  memset(out, 0, ilen * 2 + 1);
  for (size_t i = 0; i < ilen; i++) {
    sprintf(out + i * 2, "%02x", in[i]);
  }
  return strlen(out);
}

////////////////////////////////////////////////////////////////////////////////
//
//  Keep these as example of correct allocation

unsigned int
pbgp_rsa_hash(const unsigned char *input, unsigned char **md, size_t ilen)
{
  unsigned int len = EVP_MAX_MD_SIZE + 1;
  *md = xmalloc(len);
  return pbgp_rsa_uhash(input, ilen, *md);
}

unsigned int
pbgp_rsa_sign(EVP_PKEY *key, const unsigned char *data, size_t dlen, unsigned char **sig)
{
  unsigned int len = EVP_PKEY_size(key);
  *sig = xmalloc(len);
  return pbgp_rsa_usign(key, data, dlen, *sig);
}

////////////////////////////////////////////////////////////////////////////////
//
// Same as above, with user allocated memory

/**
 *
 * @param key   rsa (private) key
 * @param data  input data buffer
 * @param dlen  input data buffer length
 * @param sig   output: must be EVP_PKEY_size(key) long
 * @return      binary signature length
 */
unsigned int
pbgp_rsa_usign(EVP_PKEY *key, const unsigned char *data, unsigned int dlen, unsigned char *sig)
{
  unsigned int len;
  EVP_SignInit(&_ctx, _type);
  EVP_SignUpdate(&_ctx, data, dlen);
  EVP_SignFinal(&_ctx, sig, &len, key);
  return len;
}

/**
 * @param input   binary input buffer or string
 * @param ilen    input length in bytes
 * @param md      output buffer to store binary hash EVP_MAX_MD_SIZE + 1
 * @return        binary hash length
 */
unsigned int
pbgp_rsa_uhash(const unsigned char *input, size_t ilen, unsigned char *md)
{
  unsigned int len;
  EVP_DigestInit(&_ctx, _type);
  EVP_DigestUpdate(&_ctx, input, ilen);
  EVP_DigestFinal_ex(&_ctx, md, &len);
  return len;
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Hash a list of items
 *  Data comes from pbgp_store_t record (keys __or__ data)
 *
 * @param md      must be EVP_MAX_MD_SIZE + 1 bytes long
 * @param keys    hash keys instead of data
 */
static unsigned int
_pbgp_rsa_uhash_list(store_t *store, short keys, unsigned char *md)
{
  assert(store && md);

  unsigned int len = 0;

  EVP_DigestInit(&_ctx, _type);
  store_iterator_t *iterator = pbgp_store_iterator_open(store);

  while (1) {
    store_key_t key = STORE_KEY_INIT;
    size_t ksize = 0, dsize = 0;

    int ret = pbgp_store_iterator_uget_next_size(iterator, &ksize, &dsize);
    if (ret != 0) {
      break ;
    }
    ksize -= STORE_KEY_METADATA_LENGTH;

    unsigned char kbuf[ksize];
    memset (kbuf, 0, ksize);

    key.data = kbuf;
    key.dsize = sizeof(kbuf);

    unsigned char data[dsize];
    memset(data, 0, dsize);

    ret = pbgp_store_iterator_uget_next(iterator, &key, data, &dsize);
    if (ret != 0) {
      break ;
    }

    if (keys) {
      EVP_DigestUpdate(&_ctx, key.data, key.dsize);
    }
    else {
      EVP_DigestUpdate(&_ctx, data, dsize);
    }
  }

  pbgp_store_iterator_close(iterator);
  EVP_DigestFinal_ex(&_ctx, md, &len);
  return len;
}

unsigned int
pbgp_rsa_uhash_list_keys(store_t *store, unsigned char *md)
{
  return _pbgp_rsa_uhash_list(store, 1, md);
}

unsigned int
pbgp_rsa_uhash_list_data(store_t *store, unsigned char *md)
{
  return _pbgp_rsa_uhash_list(store, 0, md);
}

////////////////////////////////////////////////////////////////////////////////

/**
 * @return      EVP_VerifyFinal() returns 1 for a correct signature, 0 for failure
 *              and -1 if some other error occurred
 */
int
pbgp_rsa_verify(EVP_PKEY *key, const unsigned char *data, unsigned int dlen, const unsigned char *sig, unsigned int siglen)
{
  EVP_VerifyInit(&_ctx, _type);
  EVP_VerifyUpdate(&_ctx, data, dlen);
  return EVP_VerifyFinal(&_ctx, sig, siglen, key);
}
