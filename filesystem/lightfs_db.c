#include "tokudb.h"
#include "ftfs_fs.h"

int lightfs_db_create(DB **db, DB_ENV *env, uint32_t flags)
{
	*db = kmalloc(sizeof(DB), GFP_KERNEL);
	if (*db == NULL) {
		return -ENOMEM;
	}
#ifdef EMULATION
	db_create(db, env, flags);
#endif
	(*db)->dbenv = env;

	(*db)->open = lightfs_db_open;
	(*db)->close = lightfs_db_close;
	(*db)->get = lightfs_db_get;
	(*db)->put = lightfs_db_put;
	(*db)->seq_put = lightfs_db_seq_put;
	(*db)->update = lightfs_db_update;
	(*db)->del = lightfs_db_del;
	(*db)->del_multi = lightfs_db_del_multi;
	(*db)->cursor = lightfs_db_cursor;
	(*db)->rename = lightfs_db_rename;
	(*db)->hot_optimize = lightfs_db_hot_optimize;
	(*db)->hot_change_descriptor = lightfs_db_chage_descriptor;

	return 0;
}

int lightfs_db_open (DB *db, DB_TXN *txn, const char *file, const char *database, DBTYPE type, uint32_t flag, int mode)
{
	return 0;
}

int db_close (DB* db, uint32_t flag)
{
	kfree(db);

	return 0;
}

int lightfs_db_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type) {
	return lightfs_bstore_txn_get(txn, key, value, 0, type
}

int lightfs_db_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(txn, key, value, 0, type);
}

int lightfs_db_seq_put(DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(txn, key, value, 0, type);
}


int lightfs_db_update(DB *db, DB_TXN *txn, const DBT *key, DBT *value, loff_t offset, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(txn, key, value, offset, type);
}

int lightfs_db_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(txn, key, NULL, 0, type);
}

int lightfs_db_del_multi (DB *db, DB_TXN *txn, DBT *min_key, DBT *max_key, bool, enum lightfs_req_type type)
{
	//TODO:: fix del_multi
	return lightfs_bstore_txn_insert(txn, min_key, NULL, 0, type);
}

int lightfs_db_cursor (DB *db, DB_TXN *txn, DBC **dbc, enum lightfs_req_type type)
{
#ifdef EMULATION
	return db_cursor(db, txn, dbc, 0)
#else
	return lightfs_bstore_dbc_cursor(txn, dbc);
#endif
}

int lightfs_db_rename (DB *db, DB_TXN *txn, DBT *a, DBT *b, DBT *c, DBT *d, enum lightfs_req_type type)
{
	return 0;
}

int lightfs_db_hot_optimize (DB *db, DBT *a, DBT *b, int (*progress_callback)(void *progress_extra, float progress), void *progress_extra, uint64_t* loops_run)
{
	return 0;
}

int lightfs_db_change_descriptor (DB *db, DB_TXN *txn, const DBT *descriptor, uint32_t)
{
	return 0;
}
