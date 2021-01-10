#ifndef __LIGHTFS_CACHE_H__
#define __LIGHTFS_CACHE_H__

#include "tokudb.h"
#include "ftfs_fs.h"
#include <linux/hashtable.h>

struct dcache_entry {
	bool is_full;
	struct rb_root rb_root;
};

struct ht_lock_item {
	//spinlock_t lock;
	struct rw_semaphore lock;
	struct hlist_node hnode;
};

struct ht_cache_item {
	DBT key, value;
	bool is_weak_del;
	uint32_t fp;
	struct hlist_node hnode;
	struct rb_node rb_node;
	struct dcache_entry *dcache; 
};

int lightfs_cache_create(DB **, DB_ENV *, uint32_t);

#endif
