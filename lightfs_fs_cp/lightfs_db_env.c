#include "tokudb.h"
#include "ftfs_fs.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"

int lightfs_db_env_set_cachesize (DB_ENV *env, uint32_t a, uint32_t b, int c)
{
	return 0;
}

int lightfs_db_env_set_key_ops (DB_ENV *env, struct toku_db_key_operations *key_ops)
{
	db_env_set_default_bt_compare(env, key_ops->keycmp); 
	return 0;
}

void lightfs_db_env_set_update (DB_ENV *env, int (*update_function)(DB *, const DBT *key, const DBT *old_val, const DBT *extra, void (*set_val)(const DBT *new_val, void *set_extra), void *set_extra))
{
	return;
}

int lightfs_db_env_open (DB_ENV *env, const char *a, uint32_t b, int c)
{
	return 0;
}

int lightfs_db_env_checkpointing_set_period (DB_ENV *env, uint32_t a)
{
	return 0;
}

int lightfs_db_env_cleaner_set_period (DB_ENV *env, uint32_t a)
{
	return 0;
}

void lightfs_db_env_change_fsync_log_period (DB_ENV *env, uint32_t a)
{
	return;
}

int lightfs_db_env_close (DB_ENV *env, uint32_t a)
{
	lightfs_txn_hdlr_destroy();
	db_env_close(env, a);
	kfree(env);

	return 0;
}
int lightfs_db_env_txn_checkpoint (DB_ENV *env, uint32_t a, uint32_t b, uint32_t c)
{
	return 0;
}

int lightfs_db_env_get_engine_status_num_rows (DB_ENV *env, uint64_t *a)
{
	return 0;
}

int lightfs_db_env_get_engine_status_text (DB_ENV *env, char *a, int b)
{
	return 0;
}

int lightfs_db_env_log_flush (DB_ENV *env, const DB_LSN *a)
{
	return 0;
}


int lightfs_db_env_create(DB_ENV **envp, uint32_t flags)
{
	*envp = kmalloc(sizeof(DB_ENV), GFP_NOIO);
	if (*envp == NULL) {
		return -ENOMEM;
	}
	db_env_create(envp, flags);
	(*envp)->set_cachesize = lightfs_db_env_set_cachesize;
	(*envp)->set_key_ops = lightfs_db_env_set_key_ops;
	(*envp)->set_update = lightfs_db_env_set_update;
	(*envp)->open = lightfs_db_env_open;
	(*envp)->checkpointing_set_period = lightfs_db_env_checkpointing_set_period;
	(*envp)->cleaner_set_period = lightfs_db_env_cleaner_set_period;
	(*envp)->change_fsync_log_period = lightfs_db_env_change_fsync_log_period;
	(*envp)->close = lightfs_db_env_close;
	(*envp)->txn_checkpoint = lightfs_db_env_txn_checkpoint;
	(*envp)->get_engine_status_num_rows = lightfs_db_env_get_engine_status_num_rows;
	(*envp)->get_engine_status_text = lightfs_db_env_get_engine_status_text;
	(*envp)->log_flush = lightfs_db_env_log_flush;

	ftfs_error(__func__, "txn_hdlr\n");
	lightfs_txn_hdlr_init();
	

	return 0;
}
