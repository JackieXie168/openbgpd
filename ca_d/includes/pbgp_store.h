#ifndef PBGP_STORE_H
#define PBGP_STORE_H

#include <db.h>
#include <pbc/pbc.h>
#include <sys/stat.h>

#include "pbgp_schema.h"

#define DB_ERROR_PREFIX     "[*] pbgp storage error"

typedef DBC store_iterator_t;

/**
 *  We have data __or__ type (an integer from enum)
 */
typedef struct {
  store_namespace_t ns;
  store_key_index_t type;
  size_t dsize;
  unsigned char *data;
} store_key_t ;

#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))

#define STORE_KEY_INIT {0, 0, 0, NULL}

#define STORE_KEY_METADATA_LENGTH (FIELD_SIZE(store_key_t, ns) + FIELD_SIZE(store_key_t, type) + FIELD_SIZE(store_key_t, dsize))

#define STORE_KEY_SIZE(_key) (_key ? sizeof(_key->ns) + sizeof(_key->type) + sizeof(_key->dsize) + _key->dsize : 0)

#define STORE_KEY_SET_TYPE(_key, _ns, _type) (_key.ns = _ns, _key.type = _type, _key.data = (unsigned char *) &(_key.type), _key.dsize = sizeof(_type), &_key)

#define STORE_KEY_SET_DATA(_key, _ns, _data) (_key.ns = _ns, _key.type = 0, _key.data = (unsigned char *) &_data, _key.dsize = sizeof(_data), &_key)

typedef struct {
  DB *dbp;
  DB_ENV *envp;
} store_t;

#define DATABASE_HOME_DIR "."

void
pbgp_store_error_handler(const DB_ENV *envp, const const char *prefix, const char *msg);

store_t *
pbgp_store_open(const char *dbname);

int
pbgp_store_close(store_t *store);

unsigned char *
pbgp_store_key(store_key_t *key, unsigned char *buf);

store_key_t *
pbgp_store_key_set(store_key_t *key, store_namespace_t ns, unsigned char *value, size_t dsize);

////////////////////////////////////////////////////////////////////////////////

int
pbgp_store_delete(store_t *store, store_key_t *key);

int
pbgp_store_uget(store_t *store, store_key_t *key, void *data, size_t *size);

int
pbgp_store_uget_size(store_t *store, store_key_t *key, size_t *dsize);

int
pbgp_store_put(store_t *store, store_key_t *key, void *data, size_t size);

////////////////////////////////////////////////////////////////////////////////

store_iterator_t *
pbgp_store_iterator_open(store_t *store);

void
pbgp_store_iterator_close(store_iterator_t *cursorp);

int
pbgp_store_iterator_uget_next(store_iterator_t *cursorp, store_key_t *key, void *data, size_t *dsize);

int
pbgp_store_iterator_uget_next_size(store_iterator_t *cursorp, size_t *ksize, size_t *dsize);

////////////////////////////////////////////////////////////////////////////////

void
pbgp_store_put_element(store_t *store, store_key_t *key, element_t e);

int
pbgp_store_get_element(store_t *store, store_key_t *key, element_t *e);

#endif

