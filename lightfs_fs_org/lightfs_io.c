#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include "lightfs_io.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"

static struct kmem_cache *lightfs_io_large_buf_cachep;
static struct kmem_cache *lightfs_io_small_buf_cachep;


int lightfs_io_get (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_buf_get(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->len, txn_buf->buf, buf_idx);

	// cb
	// cheeze get
	// need memcpy
	// not found


	kmem_cache_free(lightfs_io_small_buf_cachep, buf);
	return 0;
}

int lightfs_io_sync_put (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_buf_set(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);

	// cb
	// cheeze sync

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

	return 0;
}

int lightfs_io_iter (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_large_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_buf_iter(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);

	// cb
	// cheeze iter
	// need memcpy
	// not found


	kmem_cache_free(lightfs_io_large_buf_cachep, buf);

	return 0;
}

int lightfs_io_transfer (DB *db, DB_C_TXN *c_txn)
{
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_large_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, c_txn->txn_id, buf_idx);
	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			switch (txn_buf->type) {
				case LIGHTFS_META_SET:
				case LIGHTFS_DATA_SET:
				case LIGHTFS_DATA_SEQ_SET:
					buf_idx = lightfs_io_set_buf_set(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);
					//db_put(txn_buf->db, NULL, &key, &value, 0);
					break;
				case LIGHTFS_META_DEL:
				case LIGHTFS_DATA_DEL:
					buf_idx = lightfs_io_set_buf_del(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, buf_idx);
					//db_del(txn_buf->db, NULL, &key, 0);
					break;
				case LIGHTFS_META_UPDATE:
				case LIGHTFS_DATA_UPDATE:
					buf_idx = lightfs_io_set_buf_update(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->update, txn_buf->buf, buf_idx);
					//value.ulen = txn_buf->update;
					//db_update(txn_buf->db, NULL, &key, &value, txn_buf->off, 0);
					break;
				case LIGHTFS_DATA_DEL_MULTI:
					buf_idx = lightfs_io_set_buf_del_multi(buf + buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, buf_idx);
					//offset = key_cnt;
					break;
				default:
					break;
			}
		}
	}

	//cheeze_write
	kmem_cache_free(lightfs_io_large_buf_cachep, buf);

	return 0;
}

int lightfs_io_commit (DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_type(buf + buf_idx, txn_buf->type, buf_idx);

	// cb
	// cheeze sync

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

	return 0;
}

int lightfs_io_close (DB_IO *db_io)
{
	kfree(db_io);
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
	kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
}

int rb_io_get (DB *db, DB_TXN_BUF *txn_buf)
{
	DBT key, value;
	dbt_setup(&key, txn_buf->key, txn_buf->key_len);
	dbt_setup(&value, txn_buf->buf+txn_buf->off, txn_buf->len);
	txn_buf->ret = db_get(txn_buf->db, NULL, &key, &value, 0);
	txn_buf->txn_buf_cb(txn_buf->completionp);

	return 0;
}

int rb_io_iter (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf)
{
	return 0;
}

int rb_io_sync_put (DB *db, DB_TXN_BUF *txn_buf)
{
	DBT key, value;
	dbt_setup(&key, txn_buf->key, txn_buf->key_len);
	dbt_setup(&value, txn_buf->buf+txn_buf->off, txn_buf->len);
	txn_buf->ret = db_put(txn_buf->db, NULL, &key, &value, 0);
	txn_buf->txn_buf_cb(txn_buf->completionp);
	return 0;
}

int rb_io_transfer (DB *db, DB_C_TXN *c_txn)
{
	DBT key, value;
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;

	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			dbt_setup(&key, txn_buf->key, txn_buf->key_len);
			dbt_setup(&value, txn_buf->buf, txn_buf->len);

			switch (txn_buf->type) {
				case LIGHTFS_META_SET:
				case LIGHTFS_DATA_SET:
				case LIGHTFS_DATA_SEQ_SET:
					db_put(txn_buf->db, NULL, &key, &value, 0);
					break;
				case LIGHTFS_META_DEL:
				case LIGHTFS_DATA_DEL:
					db_del(txn_buf->db, NULL, &key, 0);
					break;
				case LIGHTFS_META_UPDATE:
				case LIGHTFS_DATA_UPDATE:
					value.ulen = txn_buf->update;
					db_update(txn_buf->db, NULL, &key, &value, txn_buf->off, 0);
					break;
				case LIGHTFS_DATA_DEL_MULTI:
					// offset = key_cnt;
					break;
				default:
					break;
			}
		}
	}
	
	return 0;
}

int rb_io_commit (DB_TXN_BUF *txn_buf)
{
	return 0;
}

int rb_io_close (DB_IO *db_io)
{
	kfree(db_io);
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
	kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
}

int lightfs_io_create (DB_IO **db_io) {
	int ret;
	(*db_io) = (DB_IO *)kmalloc(sizeof(DB_IO), GFP_KERNEL);

	lightfs_io_large_buf_cachep = kmem_cache_create("lightfs_c_txn", LIGHTFS_IO_LARGE_BUF, 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_io_large_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_io_large_buf_cachep;
	}

	lightfs_io_small_buf_cachep = kmem_cache_create("lightfs_c_txn", LIGHTFS_IO_SMALL_BUF, 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_io_small_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_io_small_buf_cachep;
	}

#ifdef EMULATION
	(*db_io)->get = rb_io_get;
	(*db_io)->sync_put = rb_io_sync_put;
	(*db_io)->iter = rb_io_iter;
	(*db_io)->transfer = rb_io_transfer;
	(*db_io)->commit = rb_io_commit;
	(*db_io)->close = rb_io_close;
#else
	(*db_io)->get = lightfs_io_get;
	(*db_io)->iter = lightfs_io_iter;
	(*db_io)->transfer = lightfs_io_transfer;
	(*db_io)->commit = lightfs_io_commit;
	(*db_io)->close = lightfs_io_close;
#endif

out_free_io_small_buf_cachep:
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
out_free_io_large_buf_cachep:
	kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
}

