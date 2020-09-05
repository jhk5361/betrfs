#ifndef __LIGHTFS_CACHE_H__
#define __LIGHTFS_CACHE_H__

#include "tokudb.h"

struct lightfs_cache_val {
	bool is_dir;
	bool is_full;
};

int lightfs_cache_create(DB **, DB_ENV *, uint32_t);

#endif
