#include <linux/crc32.h>
#include "lightfs.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"
#include "lightfs_cache.h"

#define FSEED 0
#define SSEED 17

DEFINE_HASHTABLE (lightfs_ht_cache, HASHTABLE_BITS);
DEFINE_HASHTABLE (lightfs_ht_lock, HASHTABLE_BITS);

static struct kmem_cache *dcache_entry_cachep;
static struct kmem_cache *ht_cache_item_cachep;
static struct kmem_cache *meta_cachep;

static int _dbt_copy(DBT *to, const DBT *from) {
	memcpy(to, from, sizeof(DBT));
	to->data = kmalloc(from->size, GFP_ATOMIC);
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
	to->data = kmem_cache_alloc(meta_cachep, GFP_ATOMIC);
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

static inline void lightfs_dcache_entry_init(struct ht_cache_item *dir_ht_item) {
	dir_ht_item->dcache = kmem_cache_alloc(dcache_entry_cachep, GFP_ATOMIC);
	//dir_ht_item = kmem_cache_alloc(ht_cache_item_cachep, GFP_ATOMIC);
	dir_ht_item->dcache->is_full = true;
	dir_ht_item->dcache->rb_root = RB_ROOT;
}

/*
static void free_rb_tree(struct rb_node *node)
{
	struct rb_kv_node *kv_node = container_of(node, struct rb_kv_node, node);
	if (!node)
		return;
	if (node->rb_left)
	  free_rb_tree(node->rb_left);
	if (node->rb_right)
	  free_rb_tree(node->rb_right);
	kfree(kv_node->key.data);
	kfree(kv_node->val.data);
	kfree(kv_node);
}

static inline void lightfs_dcache_entry_free(struct ht_cache_item *dir_ht_item) {
	if (dir_ht_item->dcache) {
		free_rb_tree(dir_ht_item->dcache->rb_root.rb_node);
		kmem_cache_free(dcache_entry_cachep, dir_ht_item->dcache);
		dir_ht_item->dcache = NULL;
	}
}

*/

static inline void lightfs_ht_cache_item_init (struct ht_cache_item **ht_item, DBT *key, DBT *value) {
	*ht_item = kmem_cache_alloc(ht_cache_item_cachep, GFP_ATOMIC);
	_dbt_copy(&((*ht_item)->key), key);
	_dbt_copy_meta(&((*ht_item)->value), value);
	INIT_HLIST_NODE(&(*ht_item)->hnode);
	(*ht_item)->dcache = NULL;
}

static inline void lightfs_ht_cache_item_free (struct ht_cache_item *ht_item) {
	kfree(ht_item->key.data);
	//if (cache_item->value.data)
	kmem_cache_free(meta_cachep, ht_item->value.data);
	kmem_cache_free(ht_cache_item_cachep, ht_item);
}

/*
static struct ht_cache_item *lightfs_dcache_find_val_with_key(struct ht_cache_item *dir_ht_item, const DBT *key)
{
	struct rb_node *node = dir_ht_item->dcache->rb_root;

	while (node) {
		struct rb_cache_kv_node *tmp = container_of(node, struct rb_cache_kv_node, node);
		int result;

		result = db->dbenv->i->bt_compare(db, key, &tmp->key);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			return tmp;
		}
	}

	return NULL;
}
*/

static inline int lightfs_ht_cache_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);

	hash_for_each_possible(lightfs_ht_lock, ht_item, hnode, hkey) {
		//pr_info("들어간다1 %p\n", &ht_item->lock);
		//print_key(__func__, key->data, key->size);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_read(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, hnode, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				if (cache_item->is_weak_del) {
					memcpy(value->data, cache_item->value.data, value->size);
					cache_item->is_weak_del = 0;
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

//static inline int lightfs_ht_cache_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type, struct ftfs_inode *dir_f_inode)
static inline int lightfs_ht_cache_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);
	//static int tmp = 0;
	//DBT *dir_key = &dir_f_inode->meta_dbt;
	//uint32_t dir_hkey, dir_fp;

	hash_for_each_possible(lightfs_ht_lock, ht_item, hnode, hkey) {
		//pr_info("들어간다2 %p\n", &ht_item->lock);
		//print_key(__func__, key->data, key->size);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, hnode, hkey) {
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
		//the item which is be inserted newly
		lightfs_ht_cache_item_init(&cache_item, key, value);
		hash_add(lightfs_ht_cache, &cache_item->hnode, hkey);
		cache_item->fp = fp;
		cache_item->is_weak_del = 0;
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
		up_write(&ht_item->lock);
	}

	/*
	dir_hkey = lightfs_ht_func(FSEED, dir_key->data, dir_key->size);
	dir_kp = lightfs_ht_func(SSEED, dir_key->data, dir_key->size);
	hash_for_each_possible(lightfs_ht_cache, cache_item, hnode, hkey) {
		if (cache_item->fp == fp && !lightfs_key_cmp(cache_item->key.data, cache_item->key.size, dir_key->data, dir_key->size)) {
			// directory item
			cache_item->f


		}

	}
*/	
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

	hash_for_each_possible(lightfs_ht_lock, ht_item, hnode, hkey) {
		//pr_info("들어간다3 %p\n", &ht_item->lock);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, hnode, hkey) {
			if (cache_item->fp == fp && !lightfs_keycmp(cache_item->key.data, cache_item->key.size, key->data, key->size)) {
				found = 1;
				break;
			}
		}
		if (found) {
			hash_del(&cache_item->hnode);
		}
		//spin_unlock_bh(&ht_item->lock);
		//spin_unlock(&ht_item->lock);
		up_write(&ht_item->lock);
	}

	if (!found)
		return DB_NOTFOUND;

	lightfs_ht_cache_item_free(cache_item);

	return 0;
}

static inline int lightfs_ht_cache_weak_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	struct ht_lock_item *ht_item;
	struct ht_cache_item *cache_item;
	uint32_t hkey = lightfs_ht_func(FSEED, key->data, key->size);
	uint32_t fp = lightfs_ht_func(SSEED, key->data, key->size);
	volatile bool found = 0;

	hash_for_each_possible(lightfs_ht_lock, ht_item, hnode, hkey) {
		//pr_info("들어간다1 %p\n", &ht_item->lock);
		//spin_lock_bh(&ht_item->lock);
		//spin_lock(&ht_item->lock);
		down_write(&ht_item->lock);
		hash_for_each_possible(lightfs_ht_cache, cache_item, hnode, hkey) {
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
		ht_item = hlist_entry(lightfs_ht_lock[i].first, struct ht_lock_item, hnode);
		hash_del(&ht_item->hnode);
		kfree(ht_item);
	}
	for (i = 0; i < (1 << HASHTABLE_BITS); i++) {
		hlist_for_each_entry_safe(cache_item, hnode, &lightfs_ht_cache[i], hnode) {
			hlist_del(&cache_item->hnode);
			kfree(cache_item->key.data);
			kmem_cache_free(meta_cachep, cache_item->value.data);
			kmem_cache_free(ht_cache_item_cachep, cache_item);
		}
	}
	kmem_cache_destroy(meta_cachep);
	kmem_cache_destroy(ht_cache_item_cachep);
	kmem_cache_destroy(dcache_entry_cachep);
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
		INIT_HLIST_NODE(&ht_item->hnode);
		hlist_add_head(&ht_item->hnode, &lightfs_ht_lock[i]);
	}

	dcache_entry_cachep = kmem_cache_create("lightfs_dcache_entry_cachep", sizeof(struct dcache_entry), 0, KMEM_CACHE_FLAG, NULL);
	if (!dcache_entry_cachep)
		kmem_cache_destroy(dcache_entry_cachep);


	ht_cache_item_cachep = kmem_cache_create("lightfs_ht_cachep", sizeof(struct ht_cache_item), 0, KMEM_CACHE_FLAG, NULL);
	if (!ht_cache_item_cachep)
		kmem_cache_destroy(ht_cache_item_cachep);

	meta_cachep = kmem_cache_create("lightfs_meta_cachep", INODE_SIZE, 0, KMEM_CACHE_FLAG, NULL);
	if (!meta_cachep)
		kmem_cache_destroy(meta_cachep);

#endif

	return 0;
}
