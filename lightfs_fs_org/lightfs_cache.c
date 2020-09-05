#include "tokudb.h"
#include "ftfs_fs.h"
#include "lightfs.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"
#include "lightfs_cache.h"

int lightfs_cache_open (DB *db, DB_TXN *txn, const char *file, const char *database, DBTYPE type, uint32_t flag, int mode)
{
	return 0;
}

int lightfs_cache_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return db_cache_get(db, txn, key, 0);
}

int lightfs_cache_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return db_cache_put(db, txn, key, 0);
}

int lightfs_cache_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	return db_cache_del(db, txn, key, 0);
}


int lightfs_cache_close(DB *db, uint32_t flag)
{
	db_cache_close(db, flag);
	kfree(db);

	return 0;
}

int lightfs_cache_create(DB **db, DB_ENV *env, uint32_t flags)
{
	*db = kmalloc(sizeof(DB), GFP_KERNEL);
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

	return 0;
}
