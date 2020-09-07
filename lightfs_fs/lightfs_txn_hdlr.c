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

static struct __lightfs_txn_hdlr *txn_hdlr;

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
	//_txn_buf->txn_buf_cb = NULL;
}

static inline void lightfs_txn_buf_free(DB_TXN_BUF *txn_buf) {
	kfree(txn_buf->key);
	if (txn_buf->buf) {
		kmem_cache_free(lightfs_buf_cachep, txn_buf->buf);
	}
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
	if (txn_hdlr->txn_cnt < TXN_LIMIT) {
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

	if (txn_hdlr->txn_cnt >= TXN_LIMIT) {
		spin_lock_irqsave(&txn_hdlr->txn_hdlr_spin, irqflags);
		txn_hdlr->state = true;
		if (wq_has_sleeper(&txn_hdlr->wq)) {
			//ftfs_error(__func__, "핸들러 깨울게\n");
			wake_up_interruptible(&txn_hdlr->wq);
		}
		spin_unlock_irqrestore(&txn_hdlr->txn_hdlr_spin, irqflags);
		//ftfs_error(__func__, "TXN 잠들게\n");
		ret = wait_event_interruptible(txn_hdlr->txn_wq, lightfs_bstore_txn_check());
		//ftfs_error(__func__, "TXN 잘잤다 %d\n", ret);
	}
	*txn = kmem_cache_alloc(lightfs_txn_cachep, GFP_KERNEL);
	lightfs_txn_init(*txn);
	// lightfs_txn_init_once
	
	spin_lock(&txn_hdlr->txn_spin);
	list_add_tail(&((*txn)->txn_list), &txn_hdlr->txn_list);
	(*txn)->txn_id = txn_hdlr->txn_id++;
	txn_hdlr->txn_cnt++;
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

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	//txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//lightfs_completion_init(txn_buf->completionp);
	txn_buf_setup(txn_buf, value->data, off, value->size, type);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

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
	int i;
	uint64_t block_num = ftfs_data_key_get_blocknum(meta_key, key->size);

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	buf = kmem_cache_alloc(lightfs_dbc_buf_cachep, GFP_KERNEL);
	txn_buf_setup(txn_buf, buf, 0, cnt, type);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

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
	txn_buf->buf = (char*)kmem_cache_alloc(lightfs_buf_cachep, GFP_KERNEL);
	txn_buf_setup_cpy(txn_buf, value->data, off, value->size, type);
	txn_buf->len = PAGE_SIZE;
	alloc_txn_buf_key_from_dbt(txn_buf, key);

	//txn_buf->txn_buf_cb = lightfs_bstore_txn_sync_put_cb;
	txn_hdlr->db_io->sync_put(db, txn_buf);
	//lightfs_io_read(txn_buf);
	//wait_for_completion(txn_buf->completionp);
	//lightfs_completion_free(txn_buf->completionp);
	lightfs_txn_buf_free(txn_buf);


	//txn->state = TXN_INSERTING;

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
	DB_TXN_BUF *txn_buf = (DB_TXN_BUF *)dbc->extra;
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
			return DB_NOTFOUND;
		}
	}
	//TODO end-of-iter
	idx = copy_dbt_from_dbc(dbc, key);
	if (idx == 0) {
		return DB_NOTFOUND;
	}
	dbc->idx += idx;
	dbc->idx += copy_value_dbt_from_dbc(dbc, value);

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
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	lightfs_txn_buf_init(txn_buf);
	txn_buf->txn_id = txn->txn_id;
	txn_buf->db = db;
	if (value) { // SET, SEQ_SET, UPDATE
		txn_buf->buf = (char*)kmem_cache_alloc(lightfs_buf_cachep, GFP_KERNEL);
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
	// lightfs_txn_buf_init_once
	} else {
		txn_buf_setup(txn_buf, NULL, off, 0, type);
	}
	alloc_txn_buf_key_from_dbt(txn_buf, key);

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
	if (txn->cnt == 0) {
		list_del(&txn->txn_list);
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
	list_move_tail(&txn->txn_list, &c_txn->txn_list);
	txn_hdlr->txn_cnt--;
	spin_unlock(&txn_hdlr->txn_spin);
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
	txn_hdlr->db_io->transfer(NULL, c_txn); // should block or sleep until transfer is completed
	lightfs_c_txn_transfer_cb(c_txn);
	txn_hdlr->committing_c_txn_cnt++;
	c_txn->state |= TXN_TRANSFERING;
	//ftfs_error(__func__, "c_txn_transfer c_txn_tid:%d c_txn:%p size:%d txn_cnt: %d running_cnt:%d\n", c_txn->txn_id, c_txn, c_txn->size, txn_hdlr->txn_cnt, txn_hdlr->running_c_txn_cnt);

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
		ftfs_error(__func__, "running 개수 %d\n", txn_hdlr->running_c_txn_cnt);
	}
	
	//ftfs_error(__func__, "커밋한다 orderless:%d, ordered:%d\n", txn_hdlr->orderless_c_txn_cnt, txn_hdlr->ordered_c_txn_cnt);
	txn_hdlr->running_c_txn_cnt--;
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
			//ftfs_error(__func__, "첫번째 커밋 안됐다\n");
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
//			if (txn_hdlr->running_c_txn_id == 0) {
//				txn_hdlr->running_c_txn_id = txn->txn_id;
//			}
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
				//txn_hdlr->running_c_txn_id++;
			}
		}
		//spin_unlock(&txn_hdlr->running_c_txn_spin);
		goto txn_repeat;

transfer:
		// may sleep thread, if transfering txn is full
			// transfer a txn that have most children
		list_for_each_entry(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
			if (!(c_txn->state & TXN_TRANSFERING)) {
				ftfs_error(__func__, "별로 없나부네 먼저 보낸다.\n");
				c_txn->state = TXN_FLUSH;
				txn_hdlr->running_c_txn_id = 0;
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
		ret = wait_event_interruptible_timeout(txn_hdlr->wq, kthread_should_stop() || lightfs_txn_hdlr_check_state(), msecs_to_jiffies(TXN_FLUSH_TIME));
		//ftfs_error(__func__, "핸들러 일어났다 %d\n", ret);

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
	kmem_cache_destroy(lightfs_txn_buf_cachep);
	kmem_cache_destroy(lightfs_txn_cachep);
	kmem_cache_destroy(lightfs_c_txn_cachep);

	return 0;
}
