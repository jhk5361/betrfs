#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include "lightfs_io.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"
#include "./cheeze/cheeze.h"

//static struct kmem_cache *lightfs_io_large_buf_cachep;
static char *large_buf = NULL;
static struct kmem_cache *lightfs_io_small_buf_cachep;

extern int cheeze_init(void);
extern void cheeze_exit(void);

int rb_io_get (DB *db, DB_TXN_BUF *txn_buf)
{
	DBT key, value;
	dbt_setup(&key, txn_buf->key, txn_buf->key_len);
	dbt_setup(&value, txn_buf->buf+txn_buf->off, txn_buf->len);
	txn_buf->ret = db_get(txn_buf->db, NULL, &key, &value, 0);
	//txn_buf->txn_buf_cb(txn_buf->completionp);

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
	//txn_buf->txn_buf_cb(txn_buf->completionp);
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

int rb_io_get_multi (DB *db, DB_TXN_BUF *txn_buf)
{
	DBT key, value;
	int i;
	char *meta_key = txn_buf->key;
	uint64_t block_num = ftfs_data_key_get_blocknum(meta_key, txn_buf->key_len);

	dbt_setup(&key, txn_buf->key, txn_buf->key_len);
	for (i = 0; i < txn_buf->len; i++) {
		ftfs_data_key_set_blocknum(meta_key, key.size, block_num++);
		dbt_setup(&value, txn_buf->buf + (i * PAGE_SIZE), PAGE_SIZE);
		txn_buf->ret = db_get(txn_buf->db, NULL, &key, &value, 0);
		if (txn_buf->ret == DB_NOTFOUND) {
			memset(value.data, 0, PAGE_SIZE);
		}
	}
	txn_buf->ret = 0;

	return 0;
}

int rb_io_close (DB_IO *db_io)
{
	kfree(db_io);
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
	//kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
}

int lightfs_io_get (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_buf_get(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->len, buf_idx);

	// cb
	// cheeze get
	// need memcpy
	// not found
	//print_key(__func__, txn_buf->key, txn_buf->key_len);
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf, txn_buf->len);
	cheeze_io(&req);

	if (req.ubuf_len == 0) {
		txn_buf->ret = DB_NOTFOUND;
	} else {
		txn_buf->ret = req.ubuf_len;
	}

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

#ifdef CHEEZE
	return rb_io_get(db, txn_buf);
#endif
	return 0;
}

int lightfs_io_sync_put (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_buf_meta_set(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);

	// cb
	// cheeze sync
	//lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf);
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, NULL, 0);
	cheeze_io(&req);

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

#ifdef CHEEZE
	rb_io_sync_put(db, txn_buf);
#endif

	return 0;
}

int lightfs_io_iter (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf;
	struct cheeze_req_user req;
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);
	buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_buf_iter(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, buf_idx);

	// cb
	// cheeze iter
	// need memcpy
	// not found
	// msleep_interruptible(20);
	//ftfs_error(__func__, "iter\n");
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf, 0);
	cheeze_io(&req);
	
	//ftfs_error(__func__, "buf: %px\n len: %d\n, ubuf: %px\n, ubuf_len: %d\n", req.buf, req.buf_len, req.ubuf, req.ubuf_len);
	if (req.ubuf_len == 2) {
		//ftfs_error(__func__, "NOTFOUND\n");
		txn_buf->ret = DB_NOTFOUND;
	} else {
		txn_buf->ret = req.ubuf_len;
		//ftfs_error(__func__, "FOUND %d\n", txn_buf->ret);
	}

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

	return 0;
}

int lightfs_io_transfer (DB *db, DB_C_TXN *c_txn)
{
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;
	int buf_idx = 0;
	char *buf;
	struct cheeze_req_user req;
	uint16_t cnt = 0;
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);
	//buf = kmem_cache_alloc(lightfs_io_large_buf_cachep, GFP_KERNEL);
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);
	buf = large_buf;

	buf_idx = lightfs_io_set_txn_id(buf, c_txn->txn_id, buf_idx);
	buf_idx += 2;
	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		//txn->state 
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			switch (txn_buf->type) {
				case LIGHTFS_META_SET:
					buf_idx = lightfs_io_set_buf_meta_set(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);
					cnt++;
			//ftfs_error(__func__, "buf_idx %d, type %d, key_len %d, key %s, off %d, len %d %d", buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, sizeof(enum lightfs_req_type));
					//db_put(txn_buf->db, NULL, &key, &value, 0);
					break;
				case LIGHTFS_DATA_SET:
				case LIGHTFS_DATA_SEQ_SET:
					buf_idx = lightfs_io_set_buf_set(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);
					cnt++;
					//print_key(__func__, txn_buf->key, txn_buf->key_len);
			//ftfs_error(__func__, "buf_idx %d, type %d, key_len %d, key %s, off %d, len %d %d", buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, sizeof(enum lightfs_req_type));
					//db_put(txn_buf->db, NULL, &key, &value, 0);
					break;
				case LIGHTFS_META_DEL:
				case LIGHTFS_DATA_DEL:
					buf_idx = lightfs_io_set_buf_del(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, buf_idx);
					cnt++;
					//db_del(txn_buf->db, NULL, &key, 0);
					break;
				case LIGHTFS_META_UPDATE:
				case LIGHTFS_DATA_UPDATE:
					buf_idx = lightfs_io_set_buf_update(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->update, txn_buf->buf, buf_idx);
					cnt++;
					//value.ulen = txn_buf->update;
					//db_update(txn_buf->db, NULL, &key, &value, txn_buf->off, 0);
					break;
				case LIGHTFS_DATA_DEL_MULTI:
					buf_idx = lightfs_io_set_buf_del_multi(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, buf_idx);
					//offset = key_cnt;
					cnt++;
					break;
				default:
					ftfs_error(__func__, "다른 request 숨어있다: %d\n", txn_buf->type);
					break;
			}
		}
	}
	lightfs_io_set_cnt(buf + sizeof(uint32_t), cnt, 0); // trickty..

	//cheeze_write
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, NULL, 0);
	cheeze_io(&req);

	//kmem_cache_free(lightfs_io_large_buf_cachep, buf);
#ifdef CHEEZE
	rb_io_transfer(db, c_txn);
#endif

	return 0;
}

int lightfs_io_commit (DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_type(buf + buf_idx, txn_buf->type, buf_idx);

	// cb
	// cheeze sync
	//ftfs_error(__func__, "보낸다\n");
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, buf, 0); // last 'buf' is tricky
	//lightfs_io_set_cheeze_req(&req, buf_idx, buf, NULL, 0); // last 'buf' is tricky
	cheeze_io(&req);
	//ftfs_error(__func__, "%s\n", buf);

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

	return 0;
}

int lightfs_io_get_multi (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, txn_buf->len, buf_idx);
	buf_idx = lightfs_io_set_buf_get_multi(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, buf_idx);

	// cb
	// cheeze get
	// need memcpy
	// not found
	//print_key(__func__, txn_buf->key, txn_buf->key_len);
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf, 0);
	cheeze_io(&req);

	if (req.ubuf_len == 0) {
		txn_buf->ret = DB_NOTFOUND;
	} else {
		txn_buf->ret = req.ubuf_len;
	}

	kmem_cache_free(lightfs_io_small_buf_cachep, buf);

#ifdef CHEEZE
	return rb_io_get_multi(db, txn_buf);
#endif
	return 0;
}

int lightfs_io_close (DB_IO *db_io)
{
	cheeze_exit();
	kfree(db_io);
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
	//kmem_cache_destroy(lightfs_io_large_buf_cachep);
	kvfree(large_buf);

	return 0;
}

int lightfs_io_create (DB_IO **db_io) {
	int ret;
	(*db_io) = (DB_IO *)kmalloc(sizeof(DB_IO), GFP_KERNEL);

	/*
	lightfs_io_large_buf_cachep = kmem_cache_create("lightfs_c_txn_large", LIGHTFS_IO_LARGE_BUF, 0, KMEM_CACHE_FLAG, NULL);
	if (!lightfs_io_large_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_io_large_buf_cachep;
	}
	*/
	large_buf = (char *)kvmalloc(LIGHTFS_IO_LARGE_BUF, GFP_KERNEL);
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);

	lightfs_io_small_buf_cachep = kmem_cache_create("lightfs_c_txn_small", LIGHTFS_IO_SMALL_BUF, 0, KMEM_CACHE_FLAG, NULL);
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
	(*db_io)->get_multi = rb_io_get_multi;
#else
	(*db_io)->get = lightfs_io_get;
	(*db_io)->sync_put = lightfs_io_sync_put;
	(*db_io)->iter = lightfs_io_iter;
	(*db_io)->transfer = lightfs_io_transfer;
	(*db_io)->commit = lightfs_io_commit;
	(*db_io)->close = lightfs_io_close;
	(*db_io)->get_multi = lightfs_io_get_multi;
#endif

	ftfs_error(__func__, "cheeze_init %d\n", cheeze_init());

	return 0;

out_free_io_small_buf_cachep:
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
//out_free_io_large_buf_cachep:
	//kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
}

