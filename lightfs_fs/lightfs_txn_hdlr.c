#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include "lightfs_txn_hdlr.h"
#include "lightfs_io.h"
#include "rbtreekv.h"

//TODO: read/tid/type/transfer

static struct kmem_cache *lightfs_c_txn_cachep;
static struct kmem_cache *lightfs_txn_cachep;
static struct kmem_cache *lightfs_txn_buf_cachep;
static struct kmem_cache *lightfs_buf_cachep;
//static struct kmem_cache *lightfs_completion_cachep;
static struct kmem_cache *lightfs_dbc_cachep;
static struct kmem_cache *lightfs_dbc_buf_cachep;
static struct kmem_cache *lightfs_meta_buf_cachep;

static struct __lightfs_txn_hdlr *txn_hdlr;

static int lightfs_txn_buffer_get(struct rb_root *root, DB_TXN_BUF *txn_buf);
static DB_TXN_BUF *lightfs_txn_buffer_put(struct rb_root *root, DB_TXN_BUF *txn_buf);
static int lightfs_txn_buffer_del(struct rb_root *root, DB_TXN_BUF *txn_buf);


static inline void lightfs_c_txn_init(void *c_txn)
{
	DB_C_TXN *_c_txn = c_txn;
	INIT_LIST_HEAD(&_c_txn->c_txn_list);
	INIT_LIST_HEAD(&_c_txn->txn_list);
	INIT_LIST_HEAD(&_c_txn->children);
	_c_txn->size = 0;
	_c_txn->filter = (struct bloomfilter *)kmalloc(sizeof(struct bloomfilter) + C_TXN_BLOOM_M_BYTES, GFP_KERNEL);
	_c_txn->state = TXN_CREATED;
	_c_txn->parents = 0;
	bloomfilter_init(_c_txn->filter, C_TXN_BLOOM_M_BYTES * 8, C_TXN_BLOOM_K);
}

static inline void lightfs_c_txn_free(DB_C_TXN *c_txn)
{
	kfree(c_txn->filter);
	kmem_cache_free(lightfs_c_txn_cachep, c_txn);
}

static inline void lightfs_txn_init(void *txn)
{
	DB_TXN *_txn= txn;
	INIT_LIST_HEAD(&_txn->txn_list);
	INIT_LIST_HEAD(&_txn->txn_buf_list);
	_txn->cnt = 0;
	_txn->size = sizeof(_txn->cnt) + sizeof(_txn->size); // txn->cnt, txn->size
	_txn->state = TXN_CREATED;
	// size = cnt + tnx_buf * cnt
}

static inline void lightfs_txn_free(DB_TXN *txn) {
	kmem_cache_free(lightfs_txn_cachep, txn);
}

static inline void lightfs_txn_buf_init(void *txn_buf)
{
	DB_TXN_BUF *_txn_buf = txn_buf;
	//txn_buf->buf = NULL;
	INIT_LIST_HEAD(&_txn_buf->txn_buf_list);
	_txn_buf->is_deleted = 0;
	_txn_buf->is_rb = 0;
	//_txn_buf->txn_buf_cb = NULL;
}

static inline void lightfs_txn_buf_free(DB_TXN_BUF *txn_buf) {
	unsigned long irqflags;
	kfree(txn_buf->key);
	if (txn_buf->buf) {
		if (txn_buf->type == LIGHTFS_META_SET) {
			kmem_cache_free(lightfs_meta_buf_cachep, txn_buf->buf);
		} else {
			kmem_cache_free(lightfs_buf_cachep, txn_buf->buf);
		}
	}
#ifdef TXN_BUFFER
	if (txn_buf->is_rb) {
		spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
		lightfs_txn_buffer_del(&txn_hdlr->txn_buffer, txn_buf);
		spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
	}
#endif
	kmem_cache_free(lightfs_txn_buf_cachep, txn_buf);
}

static inline void lightfs_completion_init(void *completionp)
{
	//struct completion *completionp = (struct completion *)_completion;
	init_completion((struct completion *)completionp);
}

static inline void lightfs_completion_free(struct completion *completionp)
{
	//kmem_cache_free(lightfs_completion_cachep, completionp);
}

static inline void lightfs_dbc_init(void *dbc)
{
	DBC *cursor = dbc;
	//cursor->buf = (char *)kvmalloc(ITER_BUF_SIZE, GFP_KERNEL);
	cursor->buf = kmem_cache_alloc(lightfs_dbc_buf_cachep, GFP_KERNEL);
	cursor->buf_len = 0;
	cursor->idx = 0;
	//TODO: init_completion((struct completion *)completionp);
}

static inline void lightfs_dbc_free(DBC *dbc)
{
	//kvfree(dbc->buf);
	kmem_cache_free(lightfs_dbc_buf_cachep, dbc->buf);
	kmem_cache_free(lightfs_dbc_cachep, dbc);	
}




static bool lightfs_bstore_txn_check(void)
{
	unsigned long irqflags;
	bool ret;
	spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
	if (txn_hdlr->txn_cnt < HARD_TXN_LIMIT) {
		ret = true;
	} else {
		ret = false;
	}
	spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
	return ret;
}

int lightfs_bstore_txn_begin(DB_TXN *parent, DB_TXN **txn, uint32_t flags)
{
	unsigned long irqflags;
	int ret;	

	if (txn_hdlr->txn_cnt >= SOFT_TXN_LIMIT) {
		spin_lock_irqsave(&txn_hdlr->txn_hdlr_spin, irqflags);
		txn_hdlr->state = true;
		if (wq_has_sleeper(&txn_hdlr->wq)) {
			ftfs_error(__func__, "핸들러 깨울게\n");
			wake_up_interruptible(&txn_hdlr->wq);
		}
		spin_unlock_irqrestore(&txn_hdlr->txn_hdlr_spin, irqflags);
		//ftfs_error(__func__, "TXN 잠들게\n");
		if (txn_hdlr->txn_cnt >= HARD_TXN_LIMIT)
			ret = wait_event_interruptible(txn_hdlr->txn_wq, lightfs_bstore_txn_check());
		//ftfs_error(__func__, "TXN 잘잤다 %d\n", ret);
	}
	*txn = kmem_cache_alloc(lightfs_txn_cachep, GFP_KERNEL);
	lightfs_txn_init(*txn);
	// lightfs_txn_init_once
	
	spin_lock(&txn_hdlr->txn_spin);
	if (flags == TXN_READONLY) {
		(*txn)->state = TXN_READ;
	} else {
		list_add_tail(&((*txn)->txn_list), &txn_hdlr->txn_list);
	}
	txn_hdlr->txn_cnt++;
	(*txn)->txn_id = txn_hdlr->txn_id++;
	spin_unlock(&txn_hdlr->txn_spin);

	return 0;
}

void *lightfs_bstore_txn_get_cb(void *completionp)
{
	complete((struct completion *)completionp);
	return NULL;
}

int lightfs_bstore_txn_get(DB *db, DB_TXN *txn, DBT *key, DBT *value, uint32_t off, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf;
	int ret = 0;
	unsigned long irqflags;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	//txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//lightfs_completion_init(txn_buf->completionp);
	txn_buf_setup(txn_buf, value->data, off, value->size, type);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

#ifdef TXN_BUFFER
	spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
	if (lightfs_txn_buffer_get(&txn_hdlr->txn_buffer, txn_buf)) {
		ftfs_error(__func__, "Get Hit!\n");
		txn_buf->buf = NULL;
		spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
		lightfs_txn_buf_free(txn_buf);
		return 0;
	}
	spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
#endif
	

	//txn_buf->txn_buf_cb = lightfs_bstore_txn_get_cb;
	txn_hdlr->db_io->get(db, txn_buf);
	//lightfs_io_read(txn_buf);
	
	//wait_for_completion(txn_buf->completionp);
	//lightfs_completion_free(txn_buf->completionp);
	txn_buf->buf = NULL;


	if (txn_buf->ret == DB_NOTFOUND) {
		ret = DB_NOTFOUND;
	} else {
		//value->size = txn_buf->ret;
	}

	lightfs_txn_buf_free(txn_buf);

	return ret;
}

int lightfs_bstore_txn_get_multi(DB *db, DB_TXN *txn, DBT *key, uint32_t cnt, YDB_CALLBACK_FUNCTION f, void *extra, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf;
	int ret = 0;
	char *buf;
	char *meta_key = key->data;
	DBT value;
	int i, tmp;
	uint64_t block_num = ftfs_data_key_get_blocknum(meta_key, key->size);
	uint64_t buffer_block_num = block_num;
	volatile bool is_partial = 0;
	unsigned long irqflags;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	buf = kmem_cache_alloc(lightfs_dbc_buf_cachep, GFP_KERNEL);
	//txn_buf_setup(txn_buf, buf, 0, cnt, type);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

#ifdef TXN_BUFFER
	txn_buf_setup(txn_buf, buf, 0, PAGE_SIZE, type);
	for (i = 0; i < cnt; i++) {
		ftfs_data_key_set_blocknum(meta_key, key->size, buffer_block_num++);
		spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
		if (lightfs_txn_buffer_get(&txn_hdlr->txn_buffer, txn_buf)) {
			spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
			ftfs_error(__func__, "MGet Hit! buffer_block_num: %d\n", buffer_block_num - 1);
		} else {
			if (!is_partial) {
				is_partial = 1;
				block_num = buffer_block_num - 1;
				tmp = i;
			}
			spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
			ftfs_error(__func__, "MGet Miss! buffer_block_num: %d\n", buffer_block_num - 1);
			//ftfs_error(__func__, "Get Miss! buffer_block_num: %d\n", buffer_block_num - 1);
		}
		txn_buf->buf += PAGE_SIZE;
	}
#endif

	txn_buf_setup(txn_buf, buf, 0, cnt, type);
	ftfs_data_key_set_blocknum(meta_key, key->size, block_num);
	txn_buf->buf -= (tmp * PAGE_SIZE);


	txn_hdlr->db_io->get_multi(db, txn_buf);
	
//	if (txn_buf->ret == DB_NOTFOUND) {
//		ret = DB_NOTFOUND;
//		goto free_out;
//	}




	//dbt_alloc(&value, PAGE_SIZE);
	//value.size = PAGE_SIZE;

	for (i = 0; i < cnt; i++) {
		ftfs_data_key_set_blocknum(meta_key, key->size, block_num++);
		//memcpy(value.data, buf + (i * PAGE_SIZE), PAGE_SIZE);
		dbt_setup(&value, buf + (i * PAGE_SIZE), PAGE_SIZE);
		f(key, &value, extra);
	}
	//dbt_destroy(&value);
	
free_out:
	txn_buf->buf = NULL;

	kmem_cache_free(lightfs_dbc_buf_cachep, buf);
	lightfs_txn_buf_free(txn_buf);

	return ret;
}

void *lightfs_bstore_txn_sync_put_cb(void *completionp)
{
	complete((struct completion *)completionp);
	return NULL;
}


int lightfs_bstore_txn_sync_put(DB *db, DB_TXN *txn, DBT *key, DBT *value, uint32_t off, enum lightfs_req_type type) {
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	//txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//lightfs_completion_init(txn_buf->completionp);
	txn_buf->buf = (char*)kmem_cache_alloc(lightfs_meta_buf_cachep, GFP_KERNEL);
	txn_buf_setup_cpy(txn_buf, value->data, off, value->size, type);
	txn_buf->len = PAGE_SIZE;
	alloc_txn_buf_key_from_dbt(txn_buf, key);

	//txn_buf->txn_buf_cb = lightfs_bstore_txn_sync_put_cb;
	txn_hdlr->db_io->sync_put(db, txn_buf);
	//lightfs_io_read(txn_buf);
	//wait_for_completion(txn_buf->completionp);
	//lightfs_completion_free(txn_buf->completionp);
	kmem_cache_free(lightfs_meta_buf_cachep, txn_buf->buf);

	txn_buf->type = LIGHTFS_COMMIT;
	txn_hdlr->db_io->commit(txn_buf);

	txn_buf->buf = NULL;
	lightfs_txn_buf_free(txn_buf);

	return 0;
}

void *lightfs_bstore_dbc_cb(void *completionp)
{
	complete((struct completion *)completionp);
	return NULL;
}

int lightfs_bstore_dbc_c_get(DBC *dbc, DBT *key, DBT *value, uint32_t flags)
{
	uint32_t idx = 0;
	uint16_t size;
	DB_TXN_BUF *txn_buf = (DB_TXN_BUF *)dbc->extra;
	//print_key(__func__, key->data, key->size);
	//ftfs_error(__func__, "key_size: %d, dbc->idx: %d, dbc->buf_len %d eof: %d\n", key->size, dbc->idx, dbc->buf_len, sizeof(is_eof));
	//ftfs_error(__func__, "buf_len: %d, buf_idx: %d\n", dbc->buf_len, dbc->idx);
	if (dbc->idx >= dbc->buf_len) {
		if (flags == DB_SET_RANGE) {
			txn_buf->off = 1;
		} else {
			txn_buf->off = 0;
		}
		txn_buf->len = UINT16_MAX;
		copy_txn_buf_key_from_dbt(txn_buf, key);
		//lightfs_bstore_txn_buf_iter_next(txn_buf);
		txn_hdlr->db_io->iter(dbc->dbp, dbc, txn_buf); 
		//wait_for_completion(txn_buf->completionp);
		dbc->idx = 0;
#ifdef CHEEZE
		return dbc->cheeze_dbc->c_get(dbc->cheeze_dbc, key, value, flags);
#endif
		if (txn_buf->ret == DB_NOTFOUND) {
			ftfs_error(__func__, "NOT FOUND\n");
			return DB_NOTFOUND;
		} else {
			dbc->buf_len = txn_buf->ret;
		}
	}
	if (flags == DB_SET_RANGE) {
		if (dbc->idx != 0) {
			return 0;
		} else {
			dbc->idx += copy_dbt_from_dbc(dbc, key);
			dbc->idx += copy_value_dbt_from_dbc(dbc, value);
			return 0;
		}
	}
	//TODO end-of-iter
	size = dbc_get_size(dbc);
	if (size == 0) {
		dbc->idx += sizeof(size);
		return DB_NOTFOUND;
	} else if (size == 1) {
		dbc->idx += sizeof(size);
	} else {
		dbc->idx += copy_dbt_from_dbc(dbc, key);
		dbc->idx += copy_value_dbt_from_dbc(dbc, value);
	}

	return 0;
}

//greater or equal
int lightfs_bstore_dbc_c_getf_set_range(DBC *dbc, uint32_t flags, DBT *key, YDB_CALLBACK_FUNCTION f, void *extra)
{
	uint32_t idx = 0;
	DB_TXN_BUF *txn_buf = (DB_TXN_BUF *)dbc->extra;
	if (dbc->idx >= dbc->buf_len) {
		txn_buf->off = 1;
		txn_buf->len = flags;
		copy_txn_buf_key_from_dbt(txn_buf, key);
		//lightfs_bstore_txn_buf_iter_next(txn_buf);
		txn_hdlr->db_io->iter(dbc->dbp, dbc, txn_buf); 
		//wait_for_completion(txn_buf->completionp);
		dbc->idx = 0;
#ifdef CHEEZE
		return dbc->cheeze_dbc->c_getf_set_range(dbc->cheeze_dbc, flags, key, f, extra);
#endif
		if (txn_buf->ret == DB_NOTFOUND) {
			return DB_NOTFOUND;
		}
	}
	//TODO end-of-iter
	idx = copy_dbt_from_dbc(dbc, &dbc->key);
	if (idx == 0) {
		return DB_NOTFOUND;
	}
	dbc->idx += idx;
	dbc->idx += copy_value_dbt_from_dbc(dbc, &dbc->value);
	f(&dbc->key, &dbc->value, extra);

	return 0;
}

int lightfs_bstore_dbc_c_getf_next(DBC *dbc, uint32_t flags, YDB_CALLBACK_FUNCTION f, void *extra)
{
	uint32_t idx = 0;
	DB_TXN_BUF *txn_buf = (DB_TXN_BUF *)dbc->extra;

	// NEXT, SET_RANGE
	if (dbc->idx >= dbc->buf_len) {
		DBT key;
		char *str = "asd";
		key.data = str;
		key.size = strlen(str);
		txn_buf->off = 0;
		txn_buf->len = flags;
		//alloc_txn_buf_key_from_dbt(txn_buf, &dbc->key); //TODO:PinK
		copy_txn_buf_key_from_dbt(txn_buf, &key);
		//lightfs_bstore_txn_buf_iter_next(txn_buf);
		txn_hdlr->db_io->iter(dbc->dbp, dbc, txn_buf); 
		//wait_for_completion(txn_buf->completionp);
		dbc->idx = 0;
#ifdef CHEEZE
		return dbc->cheeze_dbc->c_getf_next(dbc->cheeze_dbc, flags, f, extra);
#endif
		if (txn_buf->ret == DB_NOTFOUND) {
			return DB_NOTFOUND;
		}
	}
	//TODO end-of-iter
	idx = copy_dbt_from_dbc(dbc, &dbc->key);
	if (idx == 0) {
		return DB_NOTFOUND;
	}
	dbc->idx += idx;
	dbc->idx += copy_value_dbt_from_dbc(dbc, &dbc->value);
	f(&dbc->key, &dbc->value, extra);

	return 0;
}

int lightfs_bstore_dbc_close(DBC *dbc)
{
	DB_TXN_BUF *txn_buf = (DB_TXN_BUF *)dbc->extra;
	//lightfs_completion_free(txn_buf->completionp);

#ifdef CHEEZE
	dbc->cheeze_dbc->c_close(dbc->cheeze_dbc);
#endif

	txn_buf->buf = NULL;
	lightfs_txn_buf_free(txn_buf);
	lightfs_dbc_free(dbc);

	return 0;
}

int lightfs_bstore_dbc_cursor(DB *db, DB_TXN *txn, DBC **dbc, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf;
	DBC *cursor;

	cursor = *dbc = kmem_cache_alloc(lightfs_dbc_cachep, GFP_KERNEL);
	lightfs_dbc_init(cursor);
	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->key = kmalloc(META_KEY_MAX_LEN, GFP_KERNEL); //TODO:META_KEY_MAX_LEY
	//txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//lightfs_completion_init(txn_buf->completionp);
	//txn_buf->txn_buf_cb = lightfs_bstore_dbc_cb;

	txn_buf_setup(txn_buf, cursor->buf, 0, 0, type);
	cursor->extra = (void *)txn_buf;
	cursor->c_get = lightfs_bstore_dbc_c_get;
	cursor->c_getf_set_range = lightfs_bstore_dbc_c_getf_set_range;
	cursor->c_getf_next = lightfs_bstore_dbc_c_getf_next;
	cursor->c_close = lightfs_bstore_dbc_close;
	cursor->dbp = db;

#ifdef CHEEZE
	db_cursor(db, txn, &cursor->cheeze_dbc, 0);
#endif

	
	return 0;
}


int lightfs_bstore_txn_insert(DB *db, DB_TXN *txn, DBT *key, DBT *value, uint32_t off, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf, *old_txn_buf;
	unsigned long irqflags;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	txn_buf->txn = txn;
	alloc_txn_buf_key_from_dbt(txn_buf, key);

	
	if (value) { // SET, SEQ_SET, UPDATE
		if (type == LIGHTFS_META_SET) {
			txn_buf->buf = (char*)kmem_cache_alloc(lightfs_meta_buf_cachep, GFP_KERNEL);	
		} else {
			txn_buf->buf = (char*)kmem_cache_alloc(lightfs_buf_cachep, GFP_KERNEL);
		}
		if (value->size == 0) {
			txn_buf->type = type;
			txn_buf->off = off;
			txn_buf->update = PAGE_SIZE - off;
			memset(txn_buf->buf + off, 0, PAGE_SIZE - off);
		} else {
			txn_buf_setup_cpy(txn_buf, value->data, off, value->size, type);
			txn_buf->update = value->size;
		}
		txn_buf->len = 4096;
#ifdef TXN_BUFFER
		spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
		if ( (old_txn_buf = lightfs_txn_buffer_put(&txn_hdlr->txn_buffer, txn_buf)) ) {
			// txn_buf_free
			if (old_txn_buf != txn_buf) {
				// txn_buf is absorbed
				//old_txn_buf->txn->cnt--;
				//old_txn_buf->txn->size -= calc_txn_buf_size(old_txn_buf);
				old_txn_buf->is_rb = 0;
				txn_buf->is_rb = 1;
				spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
				ftfs_error(__func__, "Put Buffer Hit: Delayed\n");
			} else {
				// txn_buf is canceled
				spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
				lightfs_txn_buf_free(txn_buf);
				ftfs_error(__func__, "Put Buffer Hit: Canceled\n");
				return 0;
			}
		} else {
			txn_buf->is_rb = 1;
			//
			//ftfs_error(__func__, "Put Buffer Miss\n");
			spin_unlock_irqrestore(&txn_hdlr->txn_spin, irqflags);
		}
#endif
	// lightfs_txn_buf_init_once
	} else {
		ftfs_error(__func__, "txn_buf id: %d\n", txn_buf->txn_id);
		txn_buf_setup(txn_buf, NULL, off, 0, type);
	}

	txn->cnt++;
	txn->size += calc_txn_buf_size(txn_buf);
	list_add_tail(&txn_buf->txn_buf_list, &txn->txn_buf_list);
	//txn->state = TXN_INSERTING;

	return 0;
}

int lightfs_bstore_txn_commit(DB_TXN *txn, uint32_t flags)
{
	//smp_mb();
	//TODO:: is it necessary?
	spin_lock(&txn_hdlr->txn_spin);
	if (txn->state == TXN_READ) {
		//list_del(&txn->txn_list);
		txn_hdlr->txn_cnt--;
		lightfs_txn_free(txn);
	} else {
		txn->state = TXN_COMMITTED;
	}
	spin_unlock(&txn_hdlr->txn_spin);
	return 0;
}

int lightfs_bstore_txn_abort(DB_TXN *txn)
{
	return 0;
}

int lightfs_bstore_txn_free(DB_TXN *txn)
{
	return 0;
}

static int lightfs_c_txn_create(DB_C_TXN **c_txn, enum lightfs_c_txn_state c_txn_state, bool is_new)
{
	*c_txn = kmem_cache_alloc(lightfs_c_txn_cachep, GFP_KERNEL);
	lightfs_c_txn_init(*c_txn);

	if (c_txn_state == C_TXN_ORDERED) {
		list_add_tail(&((*c_txn)->c_txn_list), &txn_hdlr->ordered_c_txn_list);
		txn_hdlr->ordered_c_txn_cnt++;
	} else {
		list_add_tail(&((*c_txn)->c_txn_list), &txn_hdlr->orderless_c_txn_list);
		txn_hdlr->orderless_c_txn_cnt++;
	}

	return 0;
}

static int lightfs_c_txn_destroy(DB_C_TXN *c_txn, enum lightfs_c_txn_state c_txn_state)
{
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;

	if (c_txn_state == C_TXN_ORDERED) {
		list_del(&c_txn->c_txn_list);
		txn_hdlr->ordered_c_txn_cnt--;
	} else {
		list_del(&c_txn->c_txn_list);
		txn_hdlr->orderless_c_txn_cnt--;
	}

	while (!list_empty(&c_txn->txn_list)) {
		txn = list_first_entry(&c_txn->txn_list, DB_TXN, txn_list);
		while(!list_empty(&txn->txn_buf_list)) {
			txn_buf = list_first_entry(&txn->txn_buf_list, DB_TXN_BUF, txn_buf_list);
			list_del(&txn_buf->txn_buf_list);
			lightfs_txn_buf_free(txn_buf);
		}
		list_del(&txn->txn_list);
		lightfs_txn_free(txn);
	}

	lightfs_c_txn_free(c_txn);
	return 0;
}

static int lightfs_c_txn_insert(DB_C_TXN *c_txn, DB_TXN *txn)
{
	DB_TXN_BUF *txn_buf;


	//ftfs_error(__func__, "TXN 이전값: %d, c_txn->size:%d\n", txn_hdlr->txn_cnt, c_txn->size);
	list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
		bloomfilter_set(c_txn->filter, txn_buf->key, txn_buf->key_len);
	}
	spin_lock(&txn_hdlr->txn_spin);
	txn->state = TXN_TRANSFERING;
	if (txn->cnt == 0) {
		list_del(&txn->txn_list);
		txn_hdlr->txn_cnt--;
		spin_unlock(&txn_hdlr->txn_spin);
		ftfs_error(__func__, "아무겂도 없다 %d\n", txn->txn_id);
		lightfs_txn_free(txn);	
		return 0;
	} else {
		list_move_tail(&txn->txn_list, &c_txn->txn_list);
		txn_hdlr->txn_cnt--;
		spin_unlock(&txn_hdlr->txn_spin);
		//ftfs_error(__func__, "있네 있어\n", txn->txn_id);
	}
	c_txn->size += txn->size;
	//ftfs_error(__func__, "TXN 줄어야돼: %d, c_txn->size:%d\n", txn_hdlr->txn_cnt, c_txn->size);
	//c_txn->state = TXN_INSERTING;

	return 0;
}

#if 0
static int lightfs_c_txn_make_relation(DB_C_TXN *existing_c_txn, DB_C_TXN *c_txn)
{
	DB_C_TXN_LIST *child;
	c_txn_list_alloc(&child, c_txn);
	c_txn->parents++;
	list_add_tail(&child->c_txn_list, &existing_c_txn->children);

	return 0;
}
#endif

static void* lightfs_c_txn_transfer_cb(void *data) {
	DB_C_TXN_LIST *committed_c_txn_list;
	DB_C_TXN *c_txn = (DB_C_TXN *)data;

	c_txn_list_alloc(&committed_c_txn_list, c_txn);
	//spin_lock(&txn_hdlr->committed_c_txn_spin);
	list_add_tail(&committed_c_txn_list->c_txn_list, &txn_hdlr->committed_c_txn_list);
	//spin_unlock(&txn_hdlr->committed_c_txn_spin);

	return NULL;
}

static int lightfs_c_txn_transfer(DB_C_TXN *c_txn)
{
	//TODO: send c_txn & add 
	//
	txn_hdlr->committing_c_txn_cnt++;
	c_txn->state |= TXN_TRANSFERING;
	txn_hdlr->db_io->transfer(NULL, c_txn); // should block or sleep until transfer is completed
	lightfs_c_txn_transfer_cb(c_txn);
	ftfs_error(__func__, "c_txn_transfer c_txn_tid:%d c_txn:%p size:%d txn_cnt: %d running_cnt:%d\n", c_txn->txn_id, c_txn, c_txn->size, txn_hdlr->txn_cnt, txn_hdlr->running_c_txn_cnt);

	return 0;
}

void *lightfs_bstore_c_txn_commit_flush_cb(void *completionp)
{
	complete((struct completion *)completionp);
	return NULL;
}


int lightfs_bstore_c_txn_commit_flush(DB_C_TXN *c_txn) {
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = c_txn->txn_id;
	//txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//lightfs_completion_init(txn_buf->completionp);
	txn_buf->type = LIGHTFS_COMMIT;

	ftfs_error(__func__, "c_txn_commit_flush c_txn_tid:%d c_txn:%p size:%d txn_cnt: %d running_cnt:%d\n", c_txn->txn_id, c_txn, c_txn->size, txn_hdlr->txn_cnt, txn_hdlr->running_c_txn_cnt);
	//txn_buf->txn_buf_cb = lightfs_bstore_c_txn_commit_flush_cb;
	txn_hdlr->db_io->commit(txn_buf);
	//wait_for_completion(txn_buf->completionp);
	//lightfs_completion_free(txn_buf->completionp);
	txn_buf->buf = NULL;
	//lightfs_txn_buf_free(txn_buf);
	kmem_cache_free(lightfs_txn_buf_cachep, txn_buf);


	//txn->state = TXN_INSERTING;

	return 0;
}



static int lightfs_c_txn_commit(DB_C_TXN *c_txn)
{
	DB_C_TXN_LIST *child;
	DB_C_TXN *child_c_txn;


	while (!list_empty(&c_txn->children)) {
		ftfs_error(__func__, "연관돼있어\n");
		child = list_first_entry(&c_txn->children, DB_C_TXN_LIST, c_txn_list);
		child_c_txn = child->c_txn_ptr;
		child_c_txn->parents--;
		if (!child_c_txn->parents) {
			list_move_tail(&child_c_txn->c_txn_list, &txn_hdlr->orderless_c_txn_list);
			txn_hdlr->orderless_c_txn_cnt++;
			txn_hdlr->ordered_c_txn_cnt--;
		}
		list_del(&child->c_txn_list);
		c_txn_list_free(child);
	}
	if (c_txn->state & TXN_FLUSH) {
		lightfs_bstore_c_txn_commit_flush(c_txn); // blocking commit flush
		//ftfs_error(__func__, "running 개수 %d\n", txn_hdlr->running_c_txn_cnt);
	}
	
	//ftfs_error(__func__, "커밋한다 orderless:%d, ordered:%d\n", txn_hdlr->orderless_c_txn_cnt, txn_hdlr->ordered_c_txn_cnt);
	//txn_hdlr->running_c_txn_cnt--;
	lightfs_c_txn_destroy(c_txn, C_TXN_ORDERLESS);

	return 0;
}


#if 0
/* 
 * we merge txn to the "merge_c_txn", if possible. 
 * if not, create a new c_txn after the "related_c_txn"
 * */
static enum lightfs_c_txn_state lightfs_txn_calc_order(DB_TXN *txn, DB_C_TXN **merge_c_txn, DB_C_TXN **related_c_txn)
{
	DB_C_TXN *c_txn;
	DB_TXN_BUF *txn_buf;
	//int relations = 0;
	int best_diff = C_TXN_LIMIT_BYTES + 1;
	int diff = 0;
	enum lightfs_c_txn_state ret = C_TXN_ORDERLESS;
	DB_C_TXN *best_c_txn = NULL, *target_c_txn = NULL;
	
	//TODO: parent 추가

	/*
	if (txn_hdlr->orderless_c_txn_cnt == 0) {
		return 0; // empty
	}
	*/
	
	list_for_each_entry_reverse(c_txn, &txn_hdlr->ordered_c_txn_list, c_txn_list) {
		if (c_txn->state == TXN_TRANSFERING) {
			continue;
		}
		diff = diff_c_txn_and_txn(c_txn, txn);
		if ((diff >= 0) && (best_diff > diff)) {
			best_c_txn = c_txn; // the file that is able to be merged
		}
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			if (bloomfilter_get(c_txn->filter, txn_buf->key, txn_buf->key_len)) {
				//relations++;
				target_c_txn = c_txn; // related file
				ret = C_TXN_ORDERED;
				goto out;
			}
		}
	}

	best_diff = C_TXN_LIMIT_BYTES + 1;
	best_c_txn = NULL;
	list_for_each_entry(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
		if (c_txn->state == TXN_TRANSFERING) {
			continue;
		}
		diff = diff_c_txn_and_txn(c_txn, txn);
		if ((diff >= 0) && (best_diff > diff)) {
			best_c_txn = c_txn; // the file that is able to be merged
		}
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			if (bloomfilter_get(c_txn->filter, txn_buf->key, txn_buf->key_len)) {
				//relations++;
				target_c_txn = c_txn; // related file
				ret = C_TXN_ORDERED;
				goto out;
			}
		}
	}

out:
	*merge_c_txn = best_c_txn;
	*related_c_txn = target_c_txn;
	return ret;
}
#endif

static int lightfs_keycmp(char *akey, uint16_t alen, char *bkey, uint16_t blen)
{
	int r;
	if (alen < blen) {
		r = memcmp(akey, bkey, alen);
		if (r)
			return r;
		return -1;
	} else if (alen > blen) {
		r = memcmp(akey, bkey, blen);
		if (r)
			return r;
		return 1;
	}
	// alen == blen
	return memcmp(akey, bkey, alen);
}


static DB_TXN_BUF *find_val_with_key(struct rb_root *root, char *key, uint16_t key_len)
{
	struct rb_node *node = root->rb_node;
	DB_TXN_BUF *tmp;
	int result;

	while (node) {
		//struct rb_kv_node *tmp = container_of(node, struct rb_kv_node, node);
		tmp = container_of(node, DB_TXN_BUF, rb_node);
		//result = db->dbenv->i->bt_compare(db, key, &(tmp->key));
		result = lightfs_keycmp(key, key_len, tmp->key, tmp->key_len);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			return tmp;
		}
	}

	return NULL;
}

static int txn_buffer_insert(struct rb_root *root, DB_TXN_BUF *node)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	DB_TXN_BUF *this;
	int result;

	while (*new) {
		this = container_of(*new, DB_TXN_BUF, rb_node);
		result = lightfs_keycmp(node->key, node->key_len, this->key, this->key_len);
		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return -1;
	}

	rb_link_node(&node->rb_node, parent, new);
	rb_insert_color(&node->rb_node, root);

	return 0;
}


static int lightfs_txn_buffer_get(struct rb_root *root, DB_TXN_BUF *txn_buf)
{
	DB_TXN_BUF *node;

	node = find_val_with_key(root, txn_buf->key, txn_buf->key_len);
	if (node == NULL) {
		return 0;
	}
	if (node->is_deleted) {
		memset(txn_buf->buf, 0, txn_buf->len);
		return 0;
	}
	memcpy(txn_buf->buf, node->buf, txn_buf->len);

	return txn_buf->len;
}

static DB_TXN_BUF *lightfs_txn_buffer_put(struct rb_root *root, DB_TXN_BUF *txn_buf)
{
	DB_TXN_BUF *node;
	int ret;

	node = find_val_with_key(root, txn_buf->key, txn_buf->key_len);
	if (node != NULL) {
		if (node->type != txn_buf->type) {
			ftfs_error(__func__, "txn_buf->type: %d, old_txn_buf->type :%d\n", txn_buf->type, node->type);
		}
		if (node->txn->state != TXN_TRANSFERING) {
			memcpy(node->buf, txn_buf->buf + txn_buf->off, txn_buf->len);
			node->off = txn_buf->off;
			node->len = txn_buf->len;
			node->update = txn_buf->update;
			node->type = txn_buf->type;
			return txn_buf;
		} else {
			rb_replace_node(&node->rb_node, &txn_buf->rb_node, root);
			return node;
		}
	}
	ret = txn_buffer_insert(root, txn_buf);
	BUG_ON(ret != 0);
	return NULL;
}

static int lightfs_txn_buffer_del(struct rb_root *root, DB_TXN_BUF *txn_buf) {
	unsigned long irqflags;

	//spin_lock_irqsave(&txn_hdlr->txn_buffer_spin, irqflags);
	rb_erase(&txn_buf->rb_node, root);
	//spin_unlock_irqrestore(&txn_hdlr->txn_buffer_spin, irqflags);
	return 0;
}

static bool lightfs_txn_hdlr_check_state(void)
{
	//TODO
	bool ret;
	spin_lock(&txn_hdlr->txn_hdlr_spin);
	ret = txn_hdlr->state;
	spin_unlock(&txn_hdlr->txn_hdlr_spin);
	return ret;
}

// TODO:: READ????
int lightfs_txn_hdlr_run(void *data)
{
	DB_C_TXN *c_txn;
	DB_TXN *txn;
	DB_C_TXN_LIST *committed_c_txn_list;
	int ret;

	while (1) {
		if (kthread_should_stop()) {
			break;
		}

commit_repeat:
		//spin_lock(&txn_hdlr->committed_c_txn_spin);
		if (list_empty(&txn_hdlr->committed_c_txn_list)) {
			//spin_unlock(&txn_hdlr->committed_c_txn_spin);
			goto txn_repeat;
		}
		committed_c_txn_list = list_first_entry(&txn_hdlr->committed_c_txn_list, DB_C_TXN_LIST, c_txn_list);
		list_del(&committed_c_txn_list->c_txn_list);
		//spin_unlock(&txn_hdlr->committed_c_txn_spin);
		c_txn = committed_c_txn_list->c_txn_ptr;
		lightfs_c_txn_commit(c_txn);

		goto commit_repeat;

txn_repeat:
		//TODO:: fsync: 1st priority
		/*
		c_txn_state = lightfs_txn_calc_order(txn, &merge_c_txn, &related_c_txn);
		if (merge_c_txn) {
			lightfs_c_txn_insert(merge_c_txn, txn);
		} else {
			lightfs_c_txn_create(&c_txn, c_txn_state);
			lightfs_c_txn_insert(c_txn, txn);
			lightfs_c_txn_make_relation(related_c_txn, c_txn);
		}
		*/



		spin_lock(&txn_hdlr->txn_spin);
		if (wq_has_sleeper(&txn_hdlr->txn_wq) && txn_hdlr->txn_cnt <= TXN_THRESHOLD) {
			//ftfs_error(__func__, "touch TXN_THRESHOLD\n");
			wake_up_all(&txn_hdlr->txn_wq);
		}
		if (list_empty(&txn_hdlr->txn_list)) {
			//ftfs_error(__func__, "TXN 비었다 cnt:%d\n", txn_hdlr->txn_cnt);
			spin_unlock(&txn_hdlr->txn_spin);
			goto transfer;
		}
		txn = list_first_entry(&txn_hdlr->txn_list, DB_TXN, txn_list);
		if (txn->state != TXN_COMMITTED) {
			//ftfs_error(__func__, "첫번째 커밋 안됐다 type: %d, cnt: %d\n", commit);
			spin_unlock(&txn_hdlr->txn_spin);
			goto wait_for_txn;
		}
		spin_unlock(&txn_hdlr->txn_spin);
		if (txn_hdlr->ordered_c_txn_cnt + txn_hdlr->orderless_c_txn_cnt > C_TXN_COMMITTING_LIMIT) {
			//ftfs_error(__func__, "c_txn 너무 많다! order:%d orderless:%d\n", txn_hdlr->ordered_c_txn_cnt, txn_hdlr->orderless_c_txn_cnt);
			goto commit_repeat;			
		}

		//spin_lock(&txn_hdlr->running_c_txn_spin);
		if (txn_hdlr->running_c_txn) {
			if (diff_c_txn_and_txn(txn_hdlr->running_c_txn, txn) < 0) { // transfer
				//ftfs_error(__func__, "어휴 꽉찼구만 얼른 보낸다.\n");
				lightfs_c_txn_transfer(txn_hdlr->running_c_txn);
				//ftfs_error(__func__, "txn_cnt: %d\n", txn_hdlr->txn_cnt)
				txn_hdlr->running_c_txn = NULL;
			} else { // can be merge
				lightfs_c_txn_insert(txn_hdlr->running_c_txn, txn);
			}
		} else {
			if (txn->size >= C_TXN_LIMIT_BYTES) {
				DB_TXN_BUF *txn_buf;
				txn_buf = list_first_entry(&txn->txn_buf_list, DB_TXN_BUF, txn_buf_list);
				ftfs_error(__func__, "크기가 크다 txn->cnt: %d, txn->size: %d, txn_buf->type: %d\n", txn->cnt, txn->size, txn_buf->type);
			}
			if (txn_hdlr->running_c_txn_cnt >= RUNNING_C_TXN_LIMIT) {
				goto commit_repeat;
			}
			lightfs_c_txn_create(&c_txn, C_TXN_ORDERLESS, 1);
			if (txn_hdlr->running_c_txn_id == 0)
				txn_hdlr->running_c_txn_id = txn->txn_id;
			c_txn->txn_id = txn_hdlr->running_c_txn_id;
			lightfs_c_txn_insert(c_txn, txn);
			txn_hdlr->running_c_txn_cnt++;
			txn_hdlr->running_c_txn = c_txn;
			if (txn_hdlr->running_c_txn_cnt >= RUNNING_C_TXN_LIMIT) {
				//ftfs_error(__func__, "TXN_FLUSH: %d\n", txn_hdlr->running_c_txn_cnt);
				c_txn->state = TXN_FLUSH;
				txn_hdlr->running_c_txn_id = 0;
				txn_hdlr->running_c_txn_cnt = 0;
				//txn_hdlr->running_c_txn_id++;
			}
		}
		//spin_unlock(&txn_hdlr->running_c_txn_spin);
		goto commit_repeat;

transfer:
		// may sleep thread, if transfering txn is full
			// transfer a txn that have most children
		list_for_each_entry(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
			if (!(c_txn->state & TXN_TRANSFERING)) {
				//ftfs_error(__func__, "별로 없나부네 먼저 보낸다.\n");
				c_txn->state = TXN_FLUSH;
				txn_hdlr->running_c_txn_id = 0;
				txn_hdlr->running_c_txn_cnt = 0;
				//txn_hdlr->running_c_txn_id++;
				lightfs_c_txn_transfer(c_txn);
				if (c_txn == txn_hdlr->running_c_txn) {
					txn_hdlr->running_c_txn = NULL;
				}
				goto commit_repeat;
			}
			if (txn_hdlr->committing_c_txn_cnt >= C_TXN_COMMITTING_LIMIT) {
				break;
			}
		}
		
wait_for_txn:
		//wait_event_interruptible_timeout(txn_hdlr->wq, kthread_should_stop() || lightfs_txn_hdlr_check_state(), msecs_to_jiffies(5000));
		//ret = wait_event_interruptible_timeout(txn_hdlr->wq, kthread_should_stop() || lightfs_txn_hdlr_check_state(), msecs_to_jiffies(TXN_FLUSH_TIME));
		ret = wait_event_interruptible_timeout(txn_hdlr->wq, kthread_should_stop(), msecs_to_jiffies(TXN_FLUSH_TIME));
		//ftfs_error(__func__, "핸들러 일어났다 %d\n", txn_hdlr->txn_cnt);

		spin_lock(&txn_hdlr->txn_hdlr_spin);
		txn_hdlr->state = false;
		spin_unlock(&txn_hdlr->txn_hdlr_spin);
	}
	return 0;
}

int lightfs_txn_hdlr_init(void)
{
	int ret;

	txn_hdlr_alloc(&txn_hdlr);
	
	lightfs_c_txn_cachep = kmem_cache_create("lightfs_c_txn", sizeof(DB_C_TXN), 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_c_txn_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_c_txn_cachep;
	}


	lightfs_txn_cachep = kmem_cache_create("lightfs_txn", sizeof(DB_TXN), 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_txn_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize txn cache.\n");
		ret = -ENOMEM;
		goto out_free_txn_cachep;
	}

	lightfs_txn_buf_cachep = kmem_cache_create("lightfs_txn_buf", sizeof(DB_TXN_BUF), 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_txn_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize txn buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_txn_buf_cachep;
	}

	lightfs_buf_cachep = kmem_cache_create("lightfs_buf", PAGE_SIZE, 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_buf_cachep;
	}

	lightfs_meta_buf_cachep = kmem_cache_create("lightfs_meta_buf", INODE_SIZE, 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_meta_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_meta_buf_cachep;
	}


	/*
	lightfs_completion_cachep = kmem_cache_create("lightfs_buf", sizeof(struct completion), 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_completion_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_completion_cachep;
	}
	*/

	lightfs_dbc_cachep = kmem_cache_create("lightfs_dbc", sizeof(DBC), 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_dbc_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize dbc cache.\n");
		ret = -ENOMEM;
		goto out_free_dbc_cachep;
	}

	lightfs_dbc_buf_cachep = kmem_cache_create("lightfs_dbc_buf", ITER_BUF_SIZE, 0, KMEM_CACHE_FLAG, NULL);

	if (!lightfs_dbc_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize dbc cache.\n");
		ret = -ENOMEM;
		goto out_free_dbc_buf_cachep;
	}

	ftfs_error(__func__, "lightfs_io_create\n");
	lightfs_io_create(&txn_hdlr->db_io);

	txn_hdlr->tsk = (struct task_struct *)kthread_run(lightfs_txn_hdlr_run, NULL, "lightfs_txn_hdlr");

	return 0;

out_free_dbc_buf_cachep:
	kmem_cache_destroy(lightfs_dbc_buf_cachep);
out_free_dbc_cachep:
	kmem_cache_destroy(lightfs_dbc_cachep);
//out_free_completion_cachep:
	//kmem_cache_destroy(lightfs_completion_cachep);
out_free_meta_buf_cachep:
	kmem_cache_destroy(lightfs_meta_buf_cachep);
out_free_buf_cachep:
	kmem_cache_destroy(lightfs_buf_cachep);
out_free_txn_buf_cachep:
	kmem_cache_destroy(lightfs_txn_buf_cachep);
out_free_txn_cachep:
	kmem_cache_destroy(lightfs_txn_cachep);
out_free_c_txn_cachep:
	kmem_cache_destroy(lightfs_c_txn_cachep);
	return ret;
}

int lightfs_txn_hdlr_destroy(void)
{
	kthread_stop(txn_hdlr->tsk);
	txn_hdlr->db_io->close(txn_hdlr->db_io);
	kmem_cache_destroy(lightfs_dbc_buf_cachep);
	kmem_cache_destroy(lightfs_dbc_cachep);
	//kmem_cache_destroy(lightfs_completion_cachep);
	kmem_cache_destroy(lightfs_buf_cachep);
	kmem_cache_destroy(lightfs_meta_buf_cachep);
	kmem_cache_destroy(lightfs_txn_buf_cachep);
	kmem_cache_destroy(lightfs_txn_cachep);
	kmem_cache_destroy(lightfs_c_txn_cachep);

	return 0;
}
