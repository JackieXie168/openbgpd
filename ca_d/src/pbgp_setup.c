#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

/**
 *  !!! WARNING: pairing_clear() WILL CLEAR THE PAIRING REFERENCE OF __ALL__ PBC ELEMENT
 *    INITIALIZED WITH THIS PAIRING SO ANY CALL TO element_clear() WILL SEGFAULT.
 *    USE THIS AT THE __VERY END__ OF CLEANUP ROUTINE, AFTER EVERY ELEMENT IS FREED !!!
 *
 */
void
pbgp_setup_clear(setup_params_t **setupp)
{
  assert(setupp && *setupp);

  setup_params_t *setup = *setupp;

  if (setup->gamma->data) {
    element_clear(setup->gamma);
  }

  if (setup->gammapow_np1->data) {
    element_clear(setup->gammapow_np1);
  }

  element_clear(setup->g);
  element_clear(setup->z);
  element_clear(setup->ibePub);

  uint32_t i = 0, n2 = setup->n * 2;

  if (setup->P) {
    for (i = 0; i < n2 - 1; i++) {
      if (setup->P[i]) {
        element_clear(setup->P[i]);
      }
    }
  }

  if (setup->pairing) {
    pairing_clear(setup->pairing);
  }

  // No need to free underlying rsa key
  EVP_PKEY_free(setup->rsa_evp);

  xfree(setup->P);
  xfree(setup);
}

/**
 *  Writes [g, ibePub, z, n, P] + [pk rsa]
 */
void
pbgp_setup_save_pubkey(setup_params_t *setup, store_t *store)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_G), setup->g);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_IBEPUB), setup->ibePub);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_Z), setup->z);
  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_N), (unsigned char *) &(setup->n), sizeof (setup->n));
  char *pem_pk = pbgp_rsa_get_pk_pem(setup->rsa_evp);
  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_PK), pem_pk, strlen(pem_pk) + 1);
  for (uint32_t i = 0; i < (setup->n * 2 - 1); i++) {
    pbgp_store_put_element(store, STORE_KEY_SET_DATA(key, SETUP_ELEMENT, i), setup->P[i]);
  }
}

/**
 * Reads [g, ibePub, z, n, P] + [pk rsa]
 *
 * @param setup must be already have been initialized with setup_init()
 *
 */
void
pbgp_setup_load_pubkey(setup_params_t *setup, store_t *store)
{
  store_key_t key = STORE_KEY_INIT;

  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_G), &setup->g);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_IBEPUB), &setup->ibePub);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_Z), &setup->z);

  size_t size = sizeof (setup->n);
  pbgp_store_uget(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_N), (unsigned char *) &setup->n, &size);

  pbgp_store_uget_size(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_PK), &size);

  char rsabuf[size];
  memset (rsabuf, 0, size);

  pbgp_store_uget(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_PK), rsabuf, &size);

  setup->rsa_evp = pbgp_rsa_get_pk(rsabuf);

  for (uint32_t i = 0; i < (setup->n * 2 - 1); i++) {
    pbgp_store_get_element(store, STORE_KEY_SET_DATA(key, SETUP_ELEMENT, i), &setup->P[i]);
  }
}

/**
 *      Writes [gamma, gammapow_np1] + [sk rsa]
 */
void
pbgp_setup_save_privkey(setup_params_t *setup, store_t *store)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_GAMMA), setup->gamma);
  pbgp_store_put_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_GAMMAPOW_NP1), setup->gammapow_np1);
  char *pem_sk = pbgp_rsa_get_sk_pem(setup->rsa_evp);
  pbgp_store_put(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_SK), pem_sk, strlen(pem_sk) + 1);
}

/**
 *      Reads [gamma, gammapow_np1] + [sk rsa]
 */
void
pbgp_setup_load_privkey(setup_params_t *setup, store_t *store)
{
  store_key_t key = STORE_KEY_INIT;
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_GAMMA), &setup->gamma);
  pbgp_store_get_element(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_GAMMAPOW_NP1), &setup->gammapow_np1);

  size_t size = 0;
  pbgp_store_uget_size(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_SK), &size);

  char rsabuf[size];
  memset (rsabuf, 0, size);

  pbgp_store_uget(store, STORE_KEY_SET_TYPE(key, SETUP, SETUP_RSA_SK), rsabuf, &size);
  setup->rsa_evp = pbgp_rsa_get_sk(rsabuf);
}

/**
 * Init group parameters.
 * @param setup   output
 */
void
pbgp_setup_pairing(setup_params_t *setup)
{
  // init group parameters
  if (pbc_param_init_set_str(setup->params, PBC_PARAM_ASCII)) {
    pbgp_fatal("pbc_param_init_set_str");
  }

  // init pairing structure through params
  pairing_init_pbc_param(setup->pairing, setup->params);

  // force symmetric pairing
  setup->pairing->G2 = setup->pairing->G1;
}

/**
 * Allocates setup structure.
 *
 *  Separated from _fill() as we use this before loading
 *    public only params from storage as well
 */
setup_params_t *
pbgp_setup_init(uint32_t n)
{
  assert(n > 1);

  uint32_t i = 0, n2 = n * 2;

  setup_params_t *setup = xmalloc(sizeof (setup_params_t));

  setup->n = n;

  pbgp_setup_pairing(setup);

  // exponent is secret
  element_init_Zr(setup->gamma, setup->pairing);

  // group element generator
  element_init_G1(setup->g, setup->pairing);

  // pubkey
  element_init_G1(setup->ibePub, setup->pairing);

  // pairing result
  element_init_GT(setup->z, setup->pairing);

  // secret key
  element_init_Zr(setup->gammapow_np1, setup->pairing);

  setup->P = xmalloc(sizeof (element_t) * n2 - 1);

  for (i = 0; i < n2 - 1; i++) {
    element_init_G1(setup->P[i], setup->pairing);
  }

  setup->rsa_evp = NULL;
  return setup;
}

void
pbgp_setup_fill(setup_params_t *setup)
{
  uint32_t i = 0, j = 0, n2 = setup->n * 2;

  element_t gpowgammai;
  element_t gammapowi;

  element_random(setup->gamma);
  element_random(setup->g);

  // ibePub = g * gamma
  element_mul_zn(setup->ibePub, setup->g, setup->gamma);

  // gamma^i
  element_init_G1(gpowgammai, setup->pairing);

  // g^gamma^i
  element_init_Zr(gammapowi, setup->pairing);

  // gamma^i = 1
  element_set1(gammapowi);

  // g^gamma^i = g
  element_set(gpowgammai, setup->g);

  // prepare to exponentiate gpowgammai
  element_pp_t p;

  mpz_t tmp_mpz;
  mpz_init(tmp_mpz);

  // store in p = preprocessing info
  element_pp_init(p, gpowgammai);

  for (i = 0, j = 0; i < n2; i++, j++) {
    if ((setup->n + 1) == i) {
      // secret key g^gamma+1 is n element
      element_set(setup->gammapow_np1, gpowgammai);

      // gammapowi = gammapowi * setup_s->gamma
      element_mul(gammapowi, gammapowi, setup->gamma);
      element_to_mpz(tmp_mpz, gammapowi);

      // gpowgammai = gpowgammai^tmp_mpz
      element_pp_pow(gpowgammai, tmp_mpz, p);

      j--;
      continue;
    }
    element_set(setup->P[j], gpowgammai);

    // gammapowi = gammapowi * setup_s->gamma
    element_mul(gammapowi, gammapowi, setup->gamma);
    element_to_mpz(tmp_mpz, gammapowi);

    // gpowgammai = gpowgammai^tmp_mpz
    element_pp_pow(gpowgammai, tmp_mpz, p);
  }

  element_clear(gpowgammai);
  element_clear(gammapowi);
  element_pp_clear(p);
  mpz_clear(tmp_mpz);

  // setup_s->z = e(P[1] = pk, P[n] = sk)
  element_pairing(setup->z, setup->P[1], setup->P[setup->n]);

  setup->rsa_evp = pbgp_rsa_generate();
}
