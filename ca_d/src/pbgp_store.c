#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbgp.h"

void
pbgp_store_error_handler(const DB_ENV *envp,
                         const const char *prefix, const char *msg)
{
  (void) envp ; /* x -Wextra  __attribute__((unused)) */
  pbgp_debug("%s: %s\n", prefix, msg);
}

store_t *
pbgp_store_open(const char *dbname)
{
  int ret = 0;
  char *homedir = NULL;

  store_t *store = xmalloc(sizeof(store_t));

  // Needed for in memory environments
  if (!dbname) {
    // env_flags |= DB_PRIVATE;
    // homedir = NULL;
  }
  else {
    homedir = realpath(DATABASE_HOME_DIR, NULL);
  }

  // keep this for future
  store->envp = NULL;

  if ((ret = db_create(&(store->dbp), store->envp, 0)) != 0) {
    pbgp_debug("db_create (%d)", ret);
    goto end;
  }

  store->dbp->set_errcall(store->dbp, pbgp_store_error_handler);
  store->dbp->set_errpfx(store->dbp, DB_ERROR_PREFIX);

  // store->envp->set_flags(store->envp, DB_LOG_AUTO_REMOVE, 1);

  if ((ret = store->dbp->open(store->dbp, NULL, dbname, NULL, DB_BTREE, DB_CREATE, 0)) != 0) {
    pbgp_debug("dbp->open (%d)", ret);
    goto end;
  }

end:
  if (ret != 0) {
    pbgp_store_close(store);
  }

  xfree(homedir);
  return store;
}

int
pbgp_store_close(store_t *store)
{
  int ret = 0;

  if (store == NULL) {
    return ret ;
  }

  if (store->dbp != NULL) {
    ret = store->dbp->close(store->dbp, 0);
    store->dbp = NULL;
  }

  if (store->envp != NULL) {
    ret &= store->envp->close(store->envp, 0);
    store->envp = NULL;
  }

  xfree(store);
  return ret;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @param buf  must be allocated by caller [STORE_KEY_SIZE(key)] bytes
 */
__inline__ unsigned char *
pbgp_store_serialize_key(store_key_t *key, unsigned char *buf)
{
  unsigned char *p = buf;
  memset(buf, 0, STORE_KEY_SIZE(key));

  memcpy(p, &(key->ns), sizeof(key->ns));
  p += sizeof(key->ns);

  memcpy(p, &(key->type), sizeof(key->type));
  p += sizeof(key->type);

  memcpy(p, &(key->dsize), sizeof(key->dsize));
  p += sizeof(key->dsize);

  memcpy(p, key->data, key->dsize);
  return buf;
}

/**
 * @param key  key->data must be allocated by caller [dsize] bytes
 */
__inline__ store_key_t *
pbgp_store_unserialize_key(unsigned char *buf, store_key_t *key)
{
  unsigned char *p = buf;

  memcpy(&(key->ns), p, sizeof(key->ns));
  p += sizeof(key->ns);

  memcpy(&(key->type), p, sizeof(key->type));
  p += sizeof(key->type);

  memcpy(&(key->dsize), p, sizeof(key->dsize));
  p += sizeof(key->dsize);

  memcpy(key->data, p, key->dsize);
  return key;
}

int
pbgp_store_delete(store_t *store, store_key_t *key)
{
  assert(store && store->dbp && key);

  DBT xkey;
  memset(&xkey, 0, sizeof (DBT));

  unsigned char buf[STORE_KEY_SIZE(key)];

  xkey.data = pbgp_store_serialize_key(key, buf);
  xkey.size = sizeof buf;

  return store->dbp->del(store->dbp, NULL, &xkey, 0);
}

/**
 * Get a record from storage.
 *
 * @param data  if NULL the function only computes data size (if found)
 *              and stores it in size pointer
 *
 * @param size  if 0 the function automatically (m)allocates needed memory
 *              that must be freed by caller
 *
 * @param key   a store_key_t already allocated by caller
 *
 * @return      0 on succes
 */
static int
_pbgp_store_uget(store_t *store, store_key_t *key, size_t *ksize, void *data, size_t *size)
{
  assert(store && store->dbp);

  if (size && 0 == *size) {
    assert(data == NULL);
  }

  if (data) {
    assert(size && *size > 0);
  }

  assert(key->dsize > 0);

  DBT xkey, xdata;

  memset(&xkey, 0, sizeof (DBT));
  memset(&xdata, 0, sizeof (DBT));

  unsigned char buf[STORE_KEY_SIZE(key)];
  xkey.data = pbgp_store_serialize_key(key, buf);
  xkey.size = sizeof buf;

  xdata.flags = DB_DBT_USERMEM;

  if (NULL == data) {
    xdata.data = NULL;
    xdata.ulen = 0;
  }
  else {
    xdata.data = data;
    xdata.ulen = *size;
  }

  DBC *cursorp = NULL;

  int ret = store->dbp->cursor(store->dbp, NULL, &cursorp, DB_TXN_SNAPSHOT);
  if (ret != 0) {
    goto end;
  }

  /* if record found ret == 0 */
  ret = cursorp->get(cursorp, &xkey, &xdata, DB_SET);
  assert(DB_BUFFER_SMALL != ret || !data);

  if (size) {
    *size = xdata.size;
  }

  if (ksize) {
    *ksize = xkey.size;
  }

end:
  if (cursorp != NULL) {
    cursorp->close(cursorp);
  }
  return ret;
}

int
pbgp_store_uget(store_t *store, store_key_t *key, void *data, size_t *size)
{
  return _pbgp_store_uget(store, key, NULL, data, size);
}

int
pbgp_store_uget_size(store_t *store, store_key_t *key, size_t *dsize)
{
  int ret = _pbgp_store_uget(store, key, NULL, NULL, dsize);
  return (ret == 0 || ret == DB_BUFFER_SMALL ? 0 : ret);
}

int
pbgp_store_put(store_t *store, store_key_t *key, void *data, size_t size)
{
  assert(store && store->dbp && key);
  DBT xkey, xdata;

  memset(&xkey, 0, sizeof (DBT));
  memset(&xdata, 0, sizeof (DBT));

  unsigned char buf[STORE_KEY_SIZE(key)];
  xkey.data = pbgp_store_serialize_key(key, buf);
  xkey.size = sizeof buf;

  xdata.data = data;
  xdata.size = size;

  /* overwrites old data */
  return store->dbp->put(store->dbp, NULL, &xkey, &xdata, 0);
}

////////////////////////////////////////////////////////////////////////////////

store_iterator_t *
pbgp_store_iterator_open(store_t *store)
{
  assert (store && store->dbp);
  store_iterator_t *cursorp = NULL;
  if (store->dbp->cursor(store->dbp, NULL, &cursorp, DB_TXN_SNAPSHOT)) {
    if (cursorp != NULL) {
      cursorp->close(cursorp);
    }
    pbgp_fatal("cannot create database cursor");
  }
  return cursorp;
}

void
pbgp_store_iterator_close(store_iterator_t *cursorp)
{
  if (cursorp != NULL) {
    cursorp->close(cursorp);
  }
}

/**
 * Get next record (when caller knows key and data size).
 *
 * @param key     memory must be allocated by caller
 * @param data    memory must be allocated by caller
 * @param ksize   if > 0 copy up to dsize bytes into key buffer\
 *                if not NULL always return record key size into this value
 * @param dsize   if > 0 copy up to dsize bytes into data buffer\
 *                if not NULL always return record data size into this value
 */
static int
_pbgp_store_iterator_uget(store_iterator_t *cursorp, store_key_t *key, size_t *ksize, void *data, size_t *dsize, uint32_t flags)
{
  assert(cursorp);
  DBT xdata, xkey;

  memset(&xdata, 0, sizeof (DBT));
  memset(&xkey, 0, sizeof (DBT));

  xdata.flags = DB_DBT_USERMEM;
  xkey.flags = DB_DBT_USERMEM;

  if (NULL == data) {
    xdata.data = NULL;
    xdata.ulen = 0;
  }
  else {
    xdata.data = data;
    xdata.ulen = *dsize;
  }

  if (key) {
    xkey.ulen = STORE_KEY_SIZE(key);
  }
  else {
    xkey.ulen = 0;
    xkey.data = NULL;
  }

  unsigned char kbuf[xkey.ulen];

  if (xkey.ulen) {
    xkey.data = kbuf;
  }

  /* if has next record ret == 0 */
  int ret = cursorp->get(cursorp, &xkey, &xdata, flags);
  assert(DB_BUFFER_SMALL != ret || (!key && !data));

  if (key && ret == 0) {
    key = pbgp_store_unserialize_key(xkey.data, key);
  }

  if (dsize) {
    *dsize = xdata.size;
  }

  if (ksize) {
    *ksize = xkey.size;
  }
  return ret;
}

int
pbgp_store_iterator_uget_next(store_iterator_t *cursorp, store_key_t *key, void *data, size_t *dsize)
{
  return _pbgp_store_iterator_uget(cursorp, key, NULL, data, dsize, DB_NEXT);
}

int
pbgp_store_iterator_uget_next_size(store_iterator_t *cursorp, size_t *ksize, size_t *dsize)
{
  int ret = _pbgp_store_iterator_uget(cursorp, NULL, ksize, NULL, dsize, DB_NEXT);
  return (ret == 0 || ret == DB_BUFFER_SMALL ? 0 : ret);
}

////////////////////////////////////////////////////////////////////////////////

void
pbgp_store_put_element(store_t *store, store_key_t *key, element_t e)
{
  int len = element_length_in_bytes(e);
  unsigned char buf[len];
  memset(buf, 0, sizeof (buf));
  element_to_bytes(buf, e);
  pbgp_store_put(store, key, buf, len);
}

/**
 *  Get an element from the database and store it in param e.
 *
 *  @param e        must be allocatend and freed by the caller
 *  @return         number of bytes read
 */
int
pbgp_store_get_element(store_t *store, store_key_t *key, element_t *e)
{
  size_t size = 0;
  if (pbgp_store_uget_size(store, key, &size)) {
    return 0;
  }
  unsigned char buf[size];
  memset (buf, 0, size);
  pbgp_store_uget(store, key, buf, &size);
  return element_from_bytes(*e, buf);
}
