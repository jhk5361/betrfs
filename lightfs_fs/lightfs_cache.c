#include <linux/crc32.h>
#include "tokudb.h"
#include "ftfs_fs.h"
#include "lightfs.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"
#include "lightfs_cache.h"

#define FSEED 0
#define SSEED 17

DEFINE_HASHTABLE (lightfs_ht_cache, HASHTABLE_BITS);
DEFINE_HASHTABLE (lightfs_ht_lock, HASHTABLE_BITS);

static struct kmem_cache *ht_cache_item_cachep;
static struct kmem_cache *meta_cachep;

static int _dbt_copy(DBT *to, const DBT *from) {
	memcpy(to, from, sizeof(DBT));
	to->data = kmalloc(from->size, GFP_NOIO);
	if (to->data == NULL) {
		return -ENOMEM;
	}
	memcpy(to->data, from->data, from->size);
	return 0;
}
static int _dbt_no_alloc_copy(DBT *to, const DBT *from) {
	memcpy(to->data, from->data, from->size);
	return 0;
}

static int _dbt_copy_meta(DBT *to, const DBT *from) {
	memcpy(to, from, sizeof(DBT));
	to->data = kmem_cache_alloc(meta_cachep, GFP_NOIO);
	if (to->data == NULL) {
		return -ENOMEM;
	}
	memcpy(to->data, from->data, from->size);
	return 0;
}


static int lightfs_keycmp(char *akey, uint16_t alen, char *bkey, uint16_t blen)
{
	int r;
	if (alen < blen) {
		r = memcmp(akey, bkey, alen);
		if (r)
			return r;
		return -1;
	} else if (alen > blen) {
		r = memcmp(akey, bkey, blen);
		if (r)
			return r;
		return 1;
	}
	// alen == blen
	return memcmp(akey, bkey, alen);
}


static inline uint32_t lightfs_ht_func (int seed, char *buf, uint32_t len) 
{
	return crc32(seed, buf, len);
}

static inline int lightfs_cache_open (DB *db, DB_TXN *txn, const char *file, const char *database, DBTYPE type, uint32_t flag, int mode)
{
	return 0;
}

static inline int lightfs_cache_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return db_cache_get(db, txn, key, value, 0);
}

static inline int lightfs_cache_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return db_cache_put(db, txn, key, value, 0);
}

static inline int lightfs_cache_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	return db_cache_del(db, txn, key, 0);
}

static inline int lightfs_cache_weak_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	return db_cache_weak_del(db, txn, key, 0);
}



static inline int lightfs_cache_close(DB *db, uint32_t flag)
{
	db_cache_close(db, flag);
	kfree(db);

	return 0;
}

static inline int lightfs_ht_cache_open (DB *db, DB_TXN *txn, const char *file, const char *database, DBTYPE type, uint32_t flag, int mode)
{
	return 0;
}

static inline int lightfs_ht_cache_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);

	hash_for_each_possible(lightfs_ht_lock, ht_item, node, hkey) {
		//pr_info("들어간다1 %p\n", &ht_item->lock);
		//print_key(__func__, key->data, key->size);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_read(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, node, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				if (cache_item->is_weak_del) {
					memcpy(value->data, cache_item->value.data, value->size);
					//spin_unlock_bh(&ht_item->lock);
					//spin_unlock(&ht_item->lock);
					up_read(&ht_item->lock);
					//pr_info("나간다1-1 %p\n", &ht_item->lock);
					return DB_FOUND_FREE;
				} else {
					memcpy(value->data, cache_item->value.data, value->size);
					//spin_unlock_bh(&ht_item->lock);
					//spin_unlock(&ht_item->lock);
					up_read(&ht_item->lock);
					//pr_info("나간다1-2 %p\n", &ht_item->lock);
					//pr_info("나간다2\n");
					return 0;
				}
			}
		}
		up_read(&ht_item->lock);
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
	}
					//pr_info("나간다3\n");
					//pr_info("나간다1-3 %p\n", &ht_item->lock);
	return DB_NOTFOUND;
}

static inline int lightfs_ht_cache_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);

	hash_for_each_possible(lightfs_ht_lock, ht_item, node, hkey) {
		//pr_info("들어간다2 %p\n", &ht_item->lock);
		//print_key(__func__, key->data, key->size);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, node, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				if (cache_item->is_weak_del) {
					//_dbt_copy_meta(&cache_item->value, value);
					//_dbt_copy_meta(&cache_item->value, value);
					_dbt_no_alloc_copy(&cache_item->value, value);
				} else {
					_dbt_no_alloc_copy(&cache_item->value, value);
				}
					//pr_info("나간다2-1 %p\n", &ht_item->lock);
				cache_item->is_weak_del = 0;
				//spin_unlock_bh(&ht_item->lock);
				//spin_unlock(&ht_item->lock);
				up_write(&ht_item->lock);
				return 0;
			}
		}
		cache_item = kmem_cache_alloc(ht_cache_item_cachep, GFP_NOIO);
		_dbt_copy(&cache_item->key, key);
		_dbt_copy_meta(&cache_item->value, value);
		INIT_HLIST_NODE(&cache_item->node);
		hash_add(lightfs_ht_cache, &cache_item->node, hkey);
		cache_item->fp = fp;
		cache_item->is_weak_del = 0;
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
		up_write(&ht_item->lock);
	}
					//pr_info("나간다2-2 %p\n", &ht_item->lock);
	return 0;
}

static inline int lightfs_ht_cache_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);
	volatile bool found = 0;

	hash_for_each_possible(lightfs_ht_lock, ht_item, node, hkey) {
		//pr_info("들어간다3 %p\n", &ht_item->lock);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, node, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				found = 1;
				break;
			}
		}
		if (found) {
			hash_del(&cache_item->node);
		}
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
		up_write(&ht_item->lock);
	}

	if (!found)
		return DB_NOTFOUND;

	kfree(cache_item->key.data);
	//if (cache_item->value.data)
	kmem_cache_free(meta_cachep, cache_item->value.data);
	kmem_cache_free(ht_cache_item_cachep, cache_item);

	return 0;
}

static inline int lightfs_ht_cache_weak_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);
	volatile bool found = 0;

	hash_for_each_possible(lightfs_ht_lock, ht_item, node, hkey) {
		//pr_info("들어간다1 %p\n", &ht_item->lock);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, node, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				found = 1;
				break;
			}
		}
		if (found) {
			cache_item->is_weak_del = 1;
		}
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
		up_write(&ht_item->lock);
	}

	if (!found)
		return DB_NOTFOUND;

	return 0;
}



static inline int lightfs_ht_cache_close(DB *db, uint32_t flag)
{
#ifdef RB_CACHE
	db_cache_close(db, flag);
	kfree(db);
#else
	int i;
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	struct hlist_node *hnode;
	for (i = 0; i < (1 << HASHTABLE_BITS); i++) {
		ht_item = hlist_entry(lightfs_ht_lock[i].first, struct ht_lock_item, node);
		hash_del(&ht_item->node);
		kfree(ht_item);
	}
	for (i = 0; i < (1 << HASHTABLE_BITS); i++) {
		hlist_for_each_entry_safe(cache_item, hnode, &lightfs_ht_cache[i], node) {
			hlist_del(&cache_item->node);
			kfree(cache_item->key.data);
			kmem_cache_free(meta_cachep, cache_item->value.data);
			kmem_cache_free(ht_cache_item_cachep, cache_item);
		}
	}
	kmem_cache_destroy(meta_cachep);
	kmem_cache_destroy(ht_cache_item_cachep);
	kfree(db);
#endif

	return 0;
}


int lightfs_cache_create(DB **db, DB_ENV *env, uint32_t flags)
{
#ifdef RB_CACHE
	*db = kmalloc(sizeof(DB), GFP_NOIO);
	if (*db == NULL) {
		return -ENOMEM;
	}
	db_cache_create(db, env, flags);
	BUG_ON((*db)->i == NULL);
	(*db)->dbenv = env;

	(*db)->open = lightfs_cache_open;
	(*db)->close = lightfs_cache_close;
	(*db)->get = lightfs_cache_get;
	(*db)->put = lightfs_cache_put;
	(*db)->del = lightfs_cache_del;
	(*db)->weak_del = lightfs_cache_weak_del;
#else
	int i;
	struct ht_lock_item *ht_item;

	*db = kmalloc(sizeof(DB), GFP_NOIO);
	if (*db == NULL) {
		return -ENOMEM;
	}
	(*db)->dbenv = env;

	(*db)->open = lightfs_ht_cache_open;
	(*db)->close = lightfs_ht_cache_close;
	(*db)->get = lightfs_ht_cache_get;
	(*db)->put = lightfs_ht_cache_put;
	(*db)->del = lightfs_ht_cache_del;
	(*db)->weak_del = lightfs_ht_cache_weak_del;


	hash_init(lightfs_ht_cache);
	hash_init(lightfs_ht_lock);
	for (i = 0; i < (1 << HASHTABLE_BITS); i++) {
		ht_item = kmalloc(sizeof(struct ht_lock_item), GFP_NOIO);
		//spin_lock_init(&ht_item->lock);
		init_rwsem(&ht_item->lock);
		INIT_HLIST_NODE(&ht_item->node);
		hlist_add_head(&ht_item->node, &lightfs_ht_lock[i]);
	}

	ht_cache_item_cachep = kmem_cache_create("lightfs_ht_cachep", sizeof(struct ht_cache_item), 0, KMEM_CACHE_FLAG, NULL);
	if (!ht_cache_item_cachep)
		kmem_cache_destroy(ht_cache_item_cachep);

	meta_cachep = kmem_cache_create("lightfs_meta_cachep", INODE_SIZE, 0, KMEM_CACHE_FLAG, NULL);
	if (!meta_cachep)
		kmem_cache_destroy(meta_cachep);

#endif

	return 0;
}
