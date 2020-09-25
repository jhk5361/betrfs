#ifndef __LIGHTFS_CACHE_H__
#define __LIGHTFS_CACHE_H__

#include "tokudb.h"
#include <linux/hashtable.h>

struct lightfs_cache_val {
	bool is_dir;
	bool is_full;
};

struct ht_lock_item {
	//spinlock_t lock;
	struct rw_semaphore lock;
	struct hlist_node node;
};

struct ht_cache_item {
	DBT key, value;
	bool is_weak_del;
	uint32_t fp;
	struct hlist_node node;
};

int lightfs_cache_create(DB **, DB_ENV *, uint32_t);

#endif
