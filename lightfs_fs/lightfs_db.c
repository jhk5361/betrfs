#include "tokudb.h"
#include "ftfs_fs.h"
#include "lightfs.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"

int lightfs_db_open (DB *db, DB_TXN *txn, const char *file, const char *database, DBTYPE type, uint32_t flag, int mode)
{
	return 0;
}

int lightfs_db_close (DB* db, uint32_t flag)
{
#ifdef EMULATION
	db_close(db, flag);
#endif
	kfree(db);

	return 0;
}

int lightfs_db_get (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type) {
	return lightfs_bstore_txn_get(db, txn, key, value, 0, type);
}

int lightfs_db_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(db, txn, key, value, 0, type);
}

int lightfs_db_sync_put (DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_sync_put(db, txn, key, value, 0, type);
}


int lightfs_db_seq_put(DB *db, DB_TXN *txn, DBT *key, DBT *value, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(db, txn, key, value, 0, type);
}


int lightfs_db_update(DB *db, DB_TXN *txn, const DBT *key, const DBT *value, loff_t offset, enum lightfs_req_type type)
{
	return lightfs_bstore_txn_insert(db, txn, key, value, offset, type);
}

int lightfs_db_del (DB *db , DB_TXN *txn, DBT *key, enum lightfs_req_type type)
{
	ftfs_error(__func__, "\n");
	return lightfs_bstore_txn_insert(db, txn, key, NULL, 0, type);
}

#ifdef PINK
int lightfs_db_del_multi (DB *db, DB_TXN *txn, DBT *min_key, uint32_t key_cnt, bool a, enum lightfs_req_type type)
{
	//TODO:: fix del_multi
	if (min_key == 0)
		return 0;
	else
		return lightfs_bstore_txn_insert(db, txn, min_key, NULL, key_cnt, type);
}
#else 
int lightfs_db_del_multi (DB *db, DB_TXN *txn, DBT *min_key, DBT *max_key, bool a, enum lightfs_req_type type)
{
	//TODO:: fix del_multi
	return lightfs_bstore_txn_insert(db, txn, min_key, NULL, 0, type);
}
#endif

int lightfs_db_cursor (DB *db, DB_TXN *txn, DBC **dbc, enum lightfs_req_type type)
{
#ifdef EMULATION
	return db_cursor(db, txn, dbc, 0);
#else
	return lightfs_bstore_dbc_cursor(db, txn, dbc, type);
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

int lightfs_db_change_descriptor (DB *db, DB_TXN *txn, const DBT *descriptor, uint32_t a)
{
	return 0;
}

int lightfs_db_create(DB **db, DB_ENV *env, uint32_t flags)
{
	*db = kmalloc(sizeof(DB), GFP_KERNEL);
	if (*db == NULL) {
		return -ENOMEM;
	}
#ifdef EMULATION
	db_create(db, env, flags);
#endif
	BUG_ON((*db)->i == NULL);
	(*db)->dbenv = env;

	(*db)->open = lightfs_db_open;
	(*db)->close = lightfs_db_close;
	(*db)->get = lightfs_db_get;
	(*db)->put = lightfs_db_put;
	(*db)->sync_put = lightfs_db_sync_put;
	(*db)->seq_put = lightfs_db_seq_put;
	(*db)->update = lightfs_db_update;
	(*db)->del = lightfs_db_del;
	(*db)->del_multi = lightfs_db_del_multi;
	(*db)->cursor = lightfs_db_cursor;
	(*db)->rename = lightfs_db_rename;
	(*db)->hot_optimize = lightfs_db_hot_optimize;
	(*db)->change_descriptor = lightfs_db_change_descriptor;

	return 0;
}
