#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include "lightfs_io.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"
#include "./cheeze/cheeze.h"

static struct kmem_cache *lightfs_io_large_buf_cachep;
//static char *large_buf = NULL;
static struct kmem_cache *lightfs_io_small_buf_cachep;

extern int cheeze_init(void);
extern void cheeze_exit(void);
static DB_IO *db_io_XXX; 

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

int rb_io_transfer (DB *db, DB_C_TXN *c_txn, void *(*cb)(void *data), void *extra)
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
	//char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	char *buf;
	uint64_t io_seq;
	struct cheeze_req_user req;

	io_seq = cheeze_prepare_io(&req, 1, NULL, false);
	buf = req.buf;
	


#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif

#ifdef MONITOR
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_buf_get(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->len, buf_idx);

	// cb
	// cheeze get
	// need memcpy
	// not found
	//print_key(__func__, txn_buf->key, txn_buf->key_len);
	//ftfs_error(__func__, "buf: %p, len: %d\n", txn_buf->buf, txn_buf->len);
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf, txn_buf->len);
	cheeze_io(&req, NULL, NULL, io_seq);

	if (req.ubuf_len == 0) {
		txn_buf->ret = DB_NOTFOUND;
	} else {
		txn_buf->ret = req.ubuf_len;
		memcpy(txn_buf->buf, buf, req.ubuf_len);
		//txn_buf->buf = buf;
	}

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif

#ifdef CHEEZE
	return rb_io_get(db, txn_buf);
#endif
	cheeze_free_io(req.id);
	return 0;
}

int lightfs_io_sync_put (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	//char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	char *buf;
	uint64_t io_seq;
	struct cheeze_req_user req;

	io_seq = cheeze_prepare_io(&req, 1, NULL, false);
	buf = req.buf;


#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif

#ifdef MONITOR
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_buf_meta_set(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, txn_buf->buf, buf_idx);

	// cb
	// cheeze sync
	//lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf);
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, NULL, 0);
	cheeze_io(&req, NULL, NULL, io_seq);

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);

#ifdef CHEEZE
	rb_io_sync_put(db, txn_buf);
#endif
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif

	cheeze_free_io(req.id);
	return 0;
}

int lightfs_io_iter (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	char *buf;
	uint64_t io_seq;
	struct cheeze_req_user req;
	int ret;

	io_seq = cheeze_prepare_io(&req, 1, NULL, false);
	buf = req.buf;
	txn_buf->buf = buf;
	//buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);

#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);

#ifdef MONITOR
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif


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
	cheeze_io(&req, NULL, NULL, io_seq);
	
	//ftfs_error(__func__, "buf: %px\n len: %d\n, ubuf: %px\n, ubuf_len: %d\n", req.buf, req.buf_len, req.ubuf, req.ubuf_len);
	if (req.ubuf_len == 2) {
		//ftfs_error(__func__, "NOTFOUND\n");
		txn_buf->ret = DB_NOTFOUND;
		ret = req.id;
	} else {
		txn_buf->ret = req.ubuf_len;
		ret = req.id;
		//txn_buf->extra = (void *)(req.id);
		//memcpy(txn_buf->buf, buf, req.ubuf_len);
		//ftfs_error(__func__, "FOUND %d\n", txn_buf->ret);
	}

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif

	//cheeze_free_io(req.id);

	return ret;
}

int lightfs_io_transfer (DB *db, DB_C_TXN *c_txn, void *(*cb)(void *data), void *extra)
{
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;
	int buf_idx = 0;
	char *buf;
	struct cheeze_req_user req;
	uint16_t cnt = 0;
	static uint64_t d_cnt = 0, md_cnt;
	struct page *page;
	void *page_buf;
	uint64_t io_seq;
	int del_multi_cnt = 0;
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);
	//buf = kmem_cache_alloc(lightfs_io_large_buf_cachep, GFP_KERNEL);
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);
	//buf = large_buf;
	
#ifdef MONITOR
	atomic64_inc(&db_io_XXX->mon.ops_num[LIGHTFS_TXN_TRANSFER]);
#endif


	if (c_txn->state & TXN_FLUSH || c_txn->state & TXN_ORDERED) {
		io_seq = cheeze_prepare_io(&req, 1, NULL, true);
	} else {
		io_seq = cheeze_prepare_io(&req, 0, NULL, true);
	}
	buf = req.buf;

	buf_idx = lightfs_io_set_txn_id(buf, c_txn->txn_id, buf_idx);
	buf_idx += 2;
	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
#ifdef TIME_CHECK
			lightfs_get_time(&txn_buf->transfer);
#endif

#ifdef MONITOR
			atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif
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
					break;
				case LIGHTFS_DATA_SET_WB:
					page = (struct page *)(txn_buf->buf);
					//lock_page(page);
					page_buf = kmap(page);
					buf_idx = lightfs_io_set_buf_set(buf, LIGHTFS_DATA_SET, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, page_buf, buf_idx);
					flush_dcache_page(page);
					kunmap(page_buf);
					end_page_writeback(page);
					//unlock_page(page);
					txn_buf->buf = NULL;
					cnt++;
					//print_key(__func__, txn_buf->key, txn_buf->key_len);
			//ftfs_error(__func__, "buf_idx %d, type %d, key_len %d, key %s, off %d, len %d %d", buf_idx, txn_buf->type, txn_buf->key_len, txn_buf->key, txn_buf->off, txn_buf->len, sizeof(enum lightfs_req_type));
					//db_put(txn_buf->db, NULL, &key, &value, 0);
					break;
				case LIGHTFS_META_DEL:
				case LIGHTFS_DATA_DEL:
					buf_idx = lightfs_io_set_buf_del(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, buf_idx);
					cnt++;
					d_cnt++;
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
					md_cnt++;
					/*
					if (del_multi_cnt++ > 10) {
						pr_info("[TID]:%d, del_multi_cnt: %d txn->size: %d, c_txn->size: %d\n, txn->cnt: %d, c_txn->cnt: %d", c_txn->txn_id, del_multi_cnt, txn->size, c_txn->size, txn->cnt, c_txn->cnt);
					}
					*/

#ifdef MONITOR
					atomic64_add(txn_buf->off, &db_io_XXX->mon.ops_num[LIGHTFS_DEL_MULTI_REAL]);
#endif
					break;
				default:
					pr_info("다른 request 숨어있다: %d\n", txn_buf->type);
					break;
			}
			BUG_ON(cnt==0);
		}
	}
	if (c_txn->state & TXN_FLUSH || c_txn->state & TXN_ORDERED) {
		//char *tmp;
		cnt++;
		//pr_info("%d\n", buf_idx);
		//tmp = buf + buf_idx;
		buf_idx = lightfs_io_set_type(buf + buf_idx, LIGHTFS_COMMIT, buf_idx);
#ifdef MONITOR
		atomic64_inc(&db_io_XXX->mon.ops_num[LIGHTFS_COMMIT]);
#endif
		//pr_info("%d tmp: %d\n", buf_idx, *tmp);
	}
	lightfs_io_set_cnt(buf + sizeof(uint32_t), cnt, 0); // trickty..
	//ftfs_error(__func__, "Delete cnt: %llu, MDelete cnt: %llu\n", d_cnt, md_cnt);
	//
	
	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			cnt++;	
		}
	}

	//cheeze_write
	
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, buf, 0);
	cheeze_io(&req, cb, extra, io_seq);

#ifdef TIME_CHECK
	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		//txn->state 
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			lightfs_get_time(&txn_buf->complete);
		}
	}
#endif


	//kmem_cache_free(lightfs_io_large_buf_cachep, buf);
#ifdef CHEEZE
	rb_io_transfer(db, c_txn);
#endif

	//if (c_txn->state & TXN_FLUSH || c_txn->state & TXN_ORDERED) 
	//	cheeze_free_io(req.id);

	return 0;
}

int lightfs_io_commit (DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	//char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	char *buf;
	uint64_t io_seq;
	struct cheeze_req_user req;

	io_seq = cheeze_prepare_io(&req, 1, NULL, false);
	buf = req.buf;


#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif


#ifdef MONITOR
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, 1, buf_idx);
	buf_idx = lightfs_io_set_type(buf + buf_idx, txn_buf->type, buf_idx);

	// cb
	// cheeze sync
	//ftfs_error(__func__, "보낸다\n");
	lightfs_io_set_cheeze_req(&req, buf_idx, buf, buf, 0); // last 'buf' is tricky
	//lightfs_io_set_cheeze_req(&req, buf_idx, buf, NULL, 0); // last 'buf' is tricky
	cheeze_io(&req, NULL, NULL, io_seq);
	//ftfs_error(__func__, "%s\n", buf);

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif
	cheeze_free_io(req.id);

	return 0;
}

int lightfs_io_get_multi (DB *db, DB_TXN_BUF *txn_buf)
{
	int buf_idx = 0;
	//char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;
	char *buf;
	uint64_t io_seq;

	io_seq = cheeze_prepare_io(&req, 1, NULL, false);
	buf = req.buf;


#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif


#ifdef MONITOR
	atomic64_add(txn_buf->len, &db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI_REAL]);
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, txn_buf->len, buf_idx);
	buf_idx = lightfs_io_set_buf_get_multi(buf, txn_buf->type, txn_buf->key_len, txn_buf->key, buf_idx);

	// cb
	// cheeze get
	// need memcpy
	// not found
	//print_key(__func__, txn_buf->key, txn_buf->key_len);
	txn_buf->buf = buf;

	lightfs_io_set_cheeze_req(&req, buf_idx, buf, txn_buf->buf, 0);
	cheeze_io(&req, NULL, NULL, io_seq);

	if (req.ubuf_len == 0) {
		txn_buf->ret = DB_NOTFOUND;
		cheeze_free_io(req.id);
	} else {
		txn_buf->ret = req.id;
	}

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif

#ifdef CHEEZE
	return rb_io_get_multi(db, txn_buf);
#endif
	return 0;
}

int lightfs_io_get_multi_reada (DB *db, DB_TXN_BUF *txn_buf, void *extra)
{
	int buf_idx = 0;
	//char *buf = kmem_cache_alloc(lightfs_io_small_buf_cachep, GFP_KERNEL);
	struct cheeze_req_user req;
	char *buf;
	uint64_t io_seq;
	struct reada_entry *ra_entry = (struct reada_entry *)extra;

	io_seq = cheeze_prepare_io(&req, 0, extra, false);
	buf = req.buf;

#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->transfer);
#endif


#ifdef MONITOR
	atomic64_add(txn_buf->len, &db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI_READA_REAL]);
	atomic64_inc(&db_io_XXX->mon.ops_num[txn_buf->type]);
#endif

	buf_idx = lightfs_io_set_txn_id(buf, txn_buf->txn_id, buf_idx);
	buf_idx = lightfs_io_set_cnt(buf + buf_idx, txn_buf->len, buf_idx);
	buf_idx = lightfs_io_set_buf_get_multi(buf, LIGHTFS_GET_MULTI, txn_buf->key_len, txn_buf->key, buf_idx); // GET_MULTI_READA --> GET_MULTI

	// cb
	// cheeze get
	// need memcpy
	// not found
	txn_buf->buf = buf;
	txn_buf->ret = 0;

	ra_entry->tag = req.id;
	ra_entry->buf = buf;

	lightfs_io_set_cheeze_req(&req, buf_idx, buf, buf, 0);
	cheeze_io(&req, NULL, NULL, io_seq);

	//kmem_cache_free(lightfs_io_small_buf_cachep, buf);
#ifdef TIME_CHECK
	lightfs_get_time(&txn_buf->complete);
#endif

#ifdef CHEEZE
	return rb_io_get_multi(db, txn_buf);
#endif
	return 0;
}


struct print_io_fmt {
	char *name[OPS_CNT];
};

int lightfs_io_close (DB_IO *db_io)
{
	struct print_io_fmt cmds;
	cmds.name[LIGHTFS_META_GET] = "LIGHTFS_META_GET";
	cmds.name[LIGHTFS_META_SET] = "LIGHTFS_META_SET";
	cmds.name[LIGHTFS_META_SYNC_SET] = "LIGHTFS_META_SYNC_SET";
	cmds.name[LIGHTFS_META_DEL] = "LIGHTFS_META_DEL";
	cmds.name[LIGHTFS_META_CURSOR] = "LIGHTFS_META_CURSOR";
	cmds.name[LIGHTFS_META_UPDATE] = "LIGHTFS_META_UPDATE";
	cmds.name[LIGHTFS_META_RENAME] = "LIGHTFS_META_RENAME";
	cmds.name[LIGHTFS_DATA_GET] = "LIGHTFS_DATA_GET";
	cmds.name[LIGHTFS_DATA_SET] = "LIGHTFS_DATA_SET";
	cmds.name[LIGHTFS_DATA_SEQ_SET] = "LIGHTFS_DATA_SEQ_SET";
	cmds.name[LIGHTFS_DATA_DEL] = "LIGHTFS_DATA_DEL";
	cmds.name[LIGHTFS_DATA_DEL_MULTI] = "LIGHTFS_DATA_DEL_MULTI";
	cmds.name[LIGHTFS_DATA_CURSOR] = "LIGHTFS_DATA_CURSOR";
	cmds.name[LIGHTFS_DATA_UPDATE] = "LIGHTFS_DATA_UPDATE";
	cmds.name[LIGHTFS_DATA_RENAME] = "LIGHTFS_DATA_RENAME,";
	cmds.name[LIGHTFS_COMMIT] = "LIGHTFS_COMMIT";
	cmds.name[LIGHTFS_GET_MULTI] = "LIGHTFS_GET_MULTI";
	cmds.name[LIGHTFS_GET_MULTI_READA] = "LIGHTFS_GET_MULTI_READA";
	cmds.name[LIGHTFS_DATA_SET_WB] = "LIGHTFS_DATA_SET_WB";
	cmds.name[LIGHTFS_GET_MULTI_REAL] = "LIGHTFS_GET_MULTI_REAL";
	cmds.name[LIGHTFS_GET_MULTI_READA_REAL] = "LIGHTFS_GET_MULTI_READA_REAL";
	cmds.name[LIGHTFS_DEL_MULTI_REAL] = "LIGHTFS_DEL_MULTI_REAL";
	cmds.name[LIGHTFS_TXN_TRANSFER] = "LIGHTFS_TXN_TRANSFER";
	cheeze_exit();
	/*
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
	kmem_cache_destroy(lightfs_io_large_buf_cachep);
	*/
	//kvfree(large_buf);

#ifdef MONITOR
	pr_info("=== LIGHTFS IO SUMMARY ===\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			[%30s]: %ld\n \
			==========================\n\n"
			, cmds.name[LIGHTFS_META_GET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_GET])
			, cmds.name[LIGHTFS_META_SET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_SET])
			, cmds.name[LIGHTFS_META_SYNC_SET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_SYNC_SET])
			, cmds.name[LIGHTFS_META_DEL], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_DEL])
			, cmds.name[LIGHTFS_META_CURSOR], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_CURSOR])
			, cmds.name[LIGHTFS_META_UPDATE], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_UPDATE])
			, cmds.name[LIGHTFS_META_RENAME], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_META_RENAME])
			, cmds.name[LIGHTFS_DATA_GET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_GET])
			, cmds.name[LIGHTFS_DATA_SET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_SET])
			, cmds.name[LIGHTFS_DATA_SEQ_SET], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_SEQ_SET])
			, cmds.name[LIGHTFS_DATA_DEL], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_DEL])
			, cmds.name[LIGHTFS_DATA_DEL_MULTI], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_DEL_MULTI])
			, cmds.name[LIGHTFS_DATA_CURSOR], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_CURSOR])
			, cmds.name[LIGHTFS_DATA_UPDATE], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_UPDATE])
			, cmds.name[LIGHTFS_DATA_RENAME], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_RENAME])
			, cmds.name[LIGHTFS_COMMIT], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_COMMIT])
			, cmds.name[LIGHTFS_GET_MULTI], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI])
			, cmds.name[LIGHTFS_GET_MULTI_READA], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI_READA])
			, cmds.name[LIGHTFS_DATA_SET_WB], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DATA_SET_WB])
			, cmds.name[LIGHTFS_TXN_TRANSFER], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_TXN_TRANSFER])
			, cmds.name[LIGHTFS_GET_MULTI_REAL], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI_REAL])
			, cmds.name[LIGHTFS_GET_MULTI_READA_REAL], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_GET_MULTI_READA_REAL])
			, cmds.name[LIGHTFS_DEL_MULTI_REAL], atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DEL_MULTI_REAL])	);
	pr_info("DEL_MULTI_REAL: %ld\n", atomic64_read(&db_io_XXX->mon.ops_num[LIGHTFS_DEL_MULTI_REAL]));
#endif

	kfree(db_io);

	return 0;
}

int lightfs_io_create (DB_IO **db_io) {
	int ret, i;
	(*db_io) = (DB_IO *)kmalloc(sizeof(DB_IO), GFP_KERNEL);

	/*
	lightfs_io_large_buf_cachep = kmem_cache_create("lightfs_c_txn_large", LIGHTFS_IO_LARGE_BUF, 0, KMEM_CACHE_FLAG, NULL);
	if (!lightfs_io_large_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_io_large_buf_cachep;
	}
	//large_buf = (char *)kmalloc(LIGHTFS_IO_LARGE_BUF, GFP_KERNEL);
	//ftfs_error(__func__, "%p\n", lightfs_io_large_buf_cachep);

	lightfs_io_small_buf_cachep = kmem_cache_create("lightfs_c_txn_small", LIGHTFS_IO_SMALL_BUF, 0, KMEM_CACHE_FLAG, NULL);
	if (!lightfs_io_small_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_io_small_buf_cachep;
	}
	*/

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
	(*db_io)->get_multi_reada = lightfs_io_get_multi_reada;
#endif

	ftfs_error(__func__, "cheeze_init %d\n", cheeze_init());
#ifdef MONITOR
	for (i = 0; i < OPS_CNT; i++) {
		atomic64_set(&((*db_io)->mon.ops_num[i]), 0);
	}
#endif

	db_io_XXX = *db_io;

	return 0;
	/*
out_free_io_small_buf_cachep:
	kmem_cache_destroy(lightfs_io_small_buf_cachep);
out_free_io_large_buf_cachep:
	kmem_cache_destroy(lightfs_io_large_buf_cachep);

	return 0;
	*/
}

