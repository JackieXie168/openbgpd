#include <check.h>
#include <stdlib.h>

#include "pbgp.h"
#include "check_pbgp.h"

#define STEPS 27

#if 0
static void ____dump__(const char *name, store_t *store) {
  uint32_t asnum = 0;
  store_iterator_t *iterator = NULL;
  store_key_t key = STORE_KEY_INIT;
  for (iterator = pbgp_store_iterator_open(store);
   pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0; ) {
    pbgp_debug("%s: %d", name, asnum);
  }
  pbgp_store_iterator_close(iterator);
  if (0 == asnum) {
    pbgp_debug("%s: (empty)", name);
  }
}
#endif

START_TEST(test_check_epoch)
{
  unsigned int _steps = 0, hsize = 0;
  unsigned char hash[EVP_MAX_MD_SIZE + 1];

  store_t
    *store_setup = pbgp_store_open(NULL),
    *store_epoch = pbgp_store_open(NULL),
    *store_added = pbgp_store_open(NULL),
    *store_revoked = pbgp_store_open(NULL),
    *store_glb_added = pbgp_store_open(NULL),
    *store_glb_revoked = pbgp_store_open(NULL);

  /////////////////////////////// JOIN SOME ASNUM (ID)

  const uint32_t as[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

  const char *pfxlist[] = {
    "123.122.121.1/24,123.122.122.1,123.122.122.1/16",
    "123.122.121.2/24,123.122.122.2,123.122.122.2/16",
    "123.122.121.3/24,123.122.122.3,123.122.122.3/16",
    "123.122.121.4/24,123.122.122.4,123.122.122.4/16",
    "123.122.121.5/24,123.122.122.5,123.122.122.5/16",
    "123.122.121.6/24,123.122.122.6,123.122.122.6/16",
    "123.122.121.7/24,123.122.122.7,123.122.122.7/16",
    "123.122.121.8/24,123.122.122.8,123.122.122.8/16",
    "123.122.121.9/24,123.122.122.9,123.122.122.9/16",
  };

  uint32_t i, n = sizeof (as) / sizeof (as[0]);

  setup_params_t *setup = pbgp_setup_init(n + 1);
  pbgp_setup_fill(setup);

  // Save ibe __and__ rsa pubkeys for client (AS)
  pbgp_setup_save_pubkey(setup, store_setup);

  // IBE keypair for CA=0 for signing prefix list
  ibe_keypair_t *ibe_keypair = NULL;
  pbgp_ibe_keypair_init(setup, &ibe_keypair);
  pbgp_ibe_keypair_gen(setup, 0, ibe_keypair);

  // Loop for each AS and join it
  for (i = 0; i < n; i++) {
    char *store_name = pbgp_generate_envelope_storage_name(as[i]);

    // store_cidr_in is __always__ in memory database
    store_t *store_cidr_in = pbgp_store_open(NULL),
      *store_cidr_out = pbgp_store_open(store_name);

    // Parse prefixes and store into cidr_in
    pbgp_store_parsed_cidr(as[i], pfxlist[i], store_cidr_in);

    // - creates witness for this asnum (on empty list of added id)
    // - updates epoch asnum storages (store_added / store_revoked)
    // - calls join_save and write the envelope to storage (disk)
    pbgp_action_join(setup,
                     ibe_keypair,
                     as[i],
                     store_cidr_in,
                     store_cidr_out,
                     store_added,
                     store_revoked,
                     store_glb_added,
                     store_glb_revoked
                     );

    pbgp_store_close(store_cidr_out);
    pbgp_store_close(store_cidr_in);
    xfree(store_name);
  }

  ////////////// UPDATE EPOCH ACCUMULATOR + GLOBAL ASNUM LIST + EPOCH SIGNATURES
  //
  //  Saves epoch (calls pbgp_epoch_save) to store
  //    This will update global storages (store_glb_added, store_glb_revoked)
  //
  pbgp_epoch_claim_new(setup,
                       store_epoch,
                       store_added,
                       store_revoked,
                       store_glb_added,
                       store_glb_revoked
                       );

  /////// SERVER SIDE WORK ENDS HERE ///////////////////////////////////////////

  // Simulate client: reload setup pubkey (sent to the AS)
  setup_params_t *client_setup = pbgp_setup_init(n + 1);
  pbgp_setup_load_pubkey(client_setup, store_setup);
  pbgp_setup_pairing(client_setup);

  // For testing purpose we re-load epoch data from storage
  //  in a real use case this will be executed by different parts
  epoch_t *epoch;

  pbgp_epoch_init(&epoch, client_setup);

  // this overwrites values in store_added / store_revoked (with themselves)
  pbgp_epoch_load(store_epoch, epoch, store_added, store_revoked);

  /////////////////////////////// START ACTIVE

  // Witness contained into envelope are outdated because there are new joined entities
  //  in the for loop above (only the latest AS joined should be updated)

  store_iterator_t *iterator = NULL;
  store_key_t key = STORE_KEY_INIT;
  uint32_t asnum = 0;

  // For each asnum in globally active id
  for (iterator = pbgp_store_iterator_open(store_glb_added);
    pbgp_store_iterator_uget_next(iterator, STORE_KEY_SET_DATA(key, ASLIST, asnum), NULL, NULL) == 0; )
  {
    char *store_name = pbgp_generate_envelope_storage_name(asnum);
    store_t *store_cidr_out = pbgp_store_open(store_name);

    uint32_t client_asnum;
    element_t client_witness;
    unsigned char *client_envelope_signature;
    size_t client_envelope_signature_size = 0;

    // pbgp_debug("join load id:%d", asnum);

    // load asnum, witness, signature from envelope for this asnum
    pbgp_join_load(client_setup, store_cidr_out, &client_asnum, &client_witness,
      &client_envelope_signature, &client_envelope_signature_size);

    fail_if(client_asnum != asnum, "pbgp_join_load :: asnum don't match");

    // compute serialized = (asnum + witness) to check rsa signature on them
    unsigned char serialized[sizeof asnum + element_length_in_bytes(client_witness)];
    memcpy(serialized, &client_asnum, sizeof client_asnum);
    element_to_bytes(serialized + sizeof client_asnum, client_witness);

    // verify envelope signature on serialized(asnum, witness)
    int ret = pbgp_rsa_verify(client_setup->rsa_evp, serialized, sizeof serialized,
      client_envelope_signature, client_envelope_signature_size);

    fail_if(ret != 1, "pbgp_rsa_verify :: wrong envelope signature");

    // update envelope witness with new added / revoked id lists
    pbgp_witness_update(client_setup, store_added, store_revoked, asnum, client_witness);
    pbgp_store_put_element(store_cidr_out, STORE_KEY_SET_TYPE(key, JOIN, JOIN_WITNESS), client_witness);

    // ret = 0 if __not__ revoked (id into accumulator)
    ret = pbgp_is_revoked(setup, asnum, epoch->accumulator, client_witness);
    fail_if(ret != 0, "pbgp_is_revoked :: != 0");

    // Loop on every prefix from join data and verify prefix signature
    store_iterator_t *_iterator = pbgp_store_iterator_open(store_cidr_out);
    while (1) {
      store_key_t key = STORE_KEY_INIT;
      size_t ksize = 0, dsize = 0;

      // Get [ cidr:asnum -> serialized(prefix + netmask + timestamp) ]
      int ret = pbgp_store_iterator_uget_next_size(_iterator, &ksize, &dsize);
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

      ret = pbgp_store_iterator_uget_next(_iterator, &key, data, &dsize);
      if (ret != 0) {
        break ;
      }

      if (CIDR == key.ns && MESSAGE == key.type) {
        store_t *message_store = pbgp_store_open(NULL);
        //
        // At this point we have
        //  - data = __signed__ serialized(prefix + netmask + timestamp)
        //  - kbuf = cidr with cidr.index = asnum
        //
        cidr_t cidr;

        assert(sizeof(cidr) == key.dsize);
        memcpy(&cidr, key.data, key.dsize);

        if (cidr.index == asnum) {
          _steps ++ ;
          // pbgp_debug("ibe verfy prefix for as %d", asnum);

          // Put [ asnum -> serialized(prefix + netmask + timestamp) ] into message storage
          store_key_t mkey = STORE_KEY_INIT;

          // ******* Messages are signed by ID(RIR=CA) id not by ID(AS) *******************
          const uint32_t signer_id = 0;

          // Store [data = message] to pass it to ibe_vrfy
          pbgp_store_put(message_store, STORE_KEY_SET_DATA(mkey, IBE, signer_id), data, sizeof(data));

          // Get signature for this prefix from join data / envelope
          size_t ssize = 0;
          cidr.index = SIGNATURE_INDEX;

          pbgp_store_uget_size(store_cidr_out, STORE_KEY_SET_DATA(mkey, CIDR, cidr), &ssize);
          assert(ssize > 0);

          // Signature is serialized, get the data buffer first
          unsigned char sbuf[ssize];

          // store_cidr_out contains join data = envelope
          pbgp_store_uget(store_cidr_out, &mkey, sbuf, &ssize);

          // Let's unserialize ibe signature for this prefix
          ibe_signature_t *ibe_signature;
          pbgp_ibe_signature_init(client_setup, &ibe_signature);
          pbgp_ibe_signature_unserialize(sbuf, ibe_signature);

          // Finally verify ibe signature for this cidr + timestamp
          unsigned int verified = pbgp_ibe_verify(client_setup, ibe_signature, message_store);
          fail_if(verified != 0, "pbgp_ibe_verify :: failed (0 = success)");

          pbgp_ibe_signature_clear(ibe_signature);
        }
        pbgp_store_close(message_store);
      }
    }
    pbgp_store_iterator_close(_iterator); // end prefix loop

    // Cleanup client (AS) data loaded from join envelope

    // __important__:  clear elements __before__ freeing setup (pairing)
    pbgp_witness_clear(client_witness);

    pbgp_store_close(store_cidr_out);

    xfree(client_envelope_signature);
    xfree(store_name);
  }
  pbgp_store_iterator_close(iterator);

  /////////////////////////////// REVOCATION CHECK
  //
  //

  // Empty epoch added list
  for (i = 0; i < n; i ++) {
    pbgp_store_delete(store_added, STORE_KEY_SET_DATA(key, ASLIST, as[i]));
  }

  // Revoke some "odd" AS ;-)
  for (i = 0; i < n; i += 2) {
    pbgp_action_revoke(as[i],
                   store_added,
                   store_revoked,
                   store_glb_added);
  }

  // Update accumulator and global list
  //    this will save epoch data to storage (again) and update store_glb_revoked
  pbgp_epoch_claim_new(setup,
                       store_epoch,
                       store_added,
                       store_revoked,
                       store_glb_added,
                       store_glb_revoked
                       );

  // Reload epoch data
  pbgp_epoch_clear(epoch);

  pbgp_epoch_init(&epoch, setup);

  // this overwrites values in store_added / store_revoked (with themselves)
  pbgp_epoch_load(store_epoch, epoch, store_added, store_revoked);

  // For each asnum check revocation
  for (i = 0; i < n; i++)
  {
    asnum = as[i];
    char *store_name = pbgp_generate_envelope_storage_name(asnum);
    store_t *store_cidr_out = pbgp_store_open(store_name);

    uint32_t client_asnum;
    element_t client_witness;
    unsigned char *client_envelope_signature;
    size_t client_envelope_signature_size = 0;

    // load asnum, witness, signature from envelope for this asnum
    pbgp_join_load(client_setup, store_cidr_out, &client_asnum, &client_witness,
      &client_envelope_signature, &client_envelope_signature_size);

    fail_if(client_asnum != asnum, "pbgp_join_load :: asnum don't match");

    // verify epoch signatures on hashed added list
    memset(hash, 0, sizeof hash);
    hsize = pbgp_rsa_uhash_list_keys(store_added, hash);
    int verified = pbgp_rsa_verify(client_setup->rsa_evp, hash, hsize, epoch->signature_added, epoch->signature_added_len);
    fail_if (verified != 1, "pbgp_rsa_verify :: added");

    // verify epoch signatures on hashed revoked list
    memset(hash, 0, sizeof hash);
    hsize = pbgp_rsa_uhash_list_keys(store_revoked, hash);
    verified = pbgp_rsa_verify(client_setup->rsa_evp, hash, hsize, epoch->signature_revoked, epoch->signature_revoked_len);
    fail_if (verified != 1, "pbgp_rsa_verify :: revoked");

    // update witness
    pbgp_witness_update(client_setup, store_added, store_revoked, client_asnum, client_witness);
    pbgp_store_put_element(store_cidr_out, STORE_KEY_SET_TYPE(key, JOIN, JOIN_WITNESS), client_witness);

    // verify epoch signatures on accumulator
    unsigned char accbuf[element_length_in_bytes(epoch->accumulator)];

    memset(accbuf, 0, sizeof (accbuf));
    hsize = element_to_bytes(accbuf, epoch->accumulator);

    verified = pbgp_rsa_verify(client_setup->rsa_evp, accbuf, element_length_in_bytes(epoch->accumulator),
                                   epoch->signature_accumulator, epoch->signature_accumulator_len);
    fail_if (verified != 1, "pbgp_rsa_verify :: accumulator");

    int revoked = pbgp_is_revoked(client_setup, client_asnum, epoch->accumulator, client_witness);
    if (asnum % 2) {
      fail_if (!revoked, "pbgp_is_revoked :: returned %d", revoked);
    }
    else {
      fail_if (revoked, "pbgp_is_revoked :: returned %d", revoked);
    }

    // Cleanup client (AS) data loaded from join envelope

    pbgp_witness_clear(client_witness);
    pbgp_store_close(store_cidr_out);

    xfree(client_envelope_signature);
    xfree(store_name);
  }

  /////////////////////////////// GLOBAL CLEANUP

  // check that all testing steps are fulfilled, keep this update
  fail_if(STEPS != _steps, "something is wrong, steps should be %d...", STEPS);

  pbgp_ibe_keypair_clear(ibe_keypair);

  pbgp_epoch_clear(epoch);
  pbgp_setup_clear(&client_setup);
  pbgp_setup_clear(&setup);

  for (i = 0; i < n; i++) {
    char *store_name = pbgp_generate_envelope_storage_name(as[i]);
    unlink(store_name);
  }

  pbgp_store_close(store_epoch);
  pbgp_store_close(store_added);
  pbgp_store_close(store_revoked);
  pbgp_store_close(store_glb_added);
  pbgp_store_close(store_glb_revoked);
}
END_TEST

Suite * make_epoch_suite(void)
{
  Suite *s = suite_create("epoch");
  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_check_epoch);
  suite_add_tcase(s, tc_core);
  return s;
}
