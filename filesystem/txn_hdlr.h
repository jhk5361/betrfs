#ifndef __TXN_HDLR__
#define __TXN_HDLR__

#include <linux/list.h>
#include <linux/spinlock.h> 
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/signal.h>
#include <linux/tqueue.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include "bloomfilter.h"
#include "tokudb.h"

#define C_TXN_LIMIT_BYTES 2 * 1024 * 1024
#define C_TXN_BLOOM_M_BYTES 308 // 512 items, p=0.1
//#define C_TXN_BLOOM_M_BYTES 791 // 512 items, p=0.01
#define C_TXN_BLOOM_K 3
#define C_TXN_COMMITTING_LIMIT 16
#define TXN_LIMIT 128 * 1024
#define TXN_THRESHOLD 64 * 1024
#define DBC_LIMIT 1024
#define ITER_BUF_SIZE 32 * 1024

struct __lightfs_txn_buffer DB_TXN_BUF;
struct __lightfs_c_txn DB_C_TXN;
struct __lightfs_c_txn_list DB_C_TXN_LIST;

struct __lightfs_txn_buffer {
	struct list_head txn_buf_list;
	char *key;
	uint16_t key_len;
	uint32_t off;
	uint32_t len;
	uint32_t tid;
	uint8_t type;
	//char buf[PAGE_SIZE];
	struct completion *completionp;
	char *buf;
	void * (*txn_buf_cb)(void *data);
	uint32_t ret;
	uint8_t ge;
};

struct __lightfs_c_txn {
	uint32_t tid;
	struct list_head c_txn_list;
	struct list_head txn_list;
	struct list_head children;
	uint32_t size;
	uint16_t parents;
	enum lightfs_txn_state state;
	struct bloomfilter *filter;
}

struct __lightfs_c_txn_list {
	DB_C_TXN *c_txn_ptr;
	struct list_head c_txn_list;
}

struct __lightfs_txn_hdlr {
	struct task_struct *tsk;
	wait_queue_head_t wq;
	wait_queue_head_t txn_wq;
	uint32_t txn_cnt;
	uint32_t ordered_c_txn_cnt;
	uint32_t orderless_c_txn_cnt;
	uint32_t committing_c_txn_cnt;
	struct list_head txn_list;
	struct list_head ordered_c_txn_list;
	struct list_head orderless_c_txn_list;
	struct list_head committed_c_txn_list;
	bool state;
	bool contention;
	spinlock_t txn_hdlr_spin;
	spinlock_t txn_spin;
	spinlock_t ordered_c_txn_spin;
	spinlock_t orderless_c_txn_spin;
	spinlock_t committed_c_txn_spin;
};

static inline void txn_hdlr_alloc(struct __lightfs_txn_hdlr **__txn_hdlr)
{
	struct __lightfs_txn_hdlr *_txn_hdlr = (struct __lightfs_txn_hdlr *)kmalloc(sizeof(struct __lightfs_txn_hdlr), GFP_KERNEL);

	_txn_hdlr->txn_cnt = 0;
	_txn_hdlr->ordered_c_txn_cnt = 0;
	_txn_hdlr->orderless_c_txn_cnt = 0;
	_txn_hdlr->committing_c_txn_cnt = 0;
	init_waitqueue_head(&_txn_hdlr->wq);
	init_waitqueue_head(&_txn_hdlr->txn_wq);
	INIT_LIST_HEAD(&_txn_hdlr->txn_list);
	INIT_LIST_HEAD(&_txn_hdlr->ordered_c_txn_list);
	INIT_LIST_HEAD(&_txn_hdlr->orderless_c_txn_list);
	INIT_LIST_HEAD(&_txn_hdlr->committed_c_txn_list);
	spin_lock_init(&_txn_hdlr->txn_hdlr_spin);
	spin_lock_init(&_txn_hdlr->txn_spin);
	spin_lock_init(&_txn_hdlr->ordered_c_txn_spin);
	spin_lock_init(&_txn_hdlr->orderless_c_txn_spin);
	spin_lock_init(&_txn_hdlr->committed_c_txn_spin);
	_txn_hdlr->state = false;
	_txn_hdlr->contention = false;
	*__txn_hdlr = _txn_hdlr;
}

static inline void c_txn_list_alloc(DB_C_TXN_LIST **c_txn_list, DB_C_TXN *c_txn)
{
	*c_txn_list = kmalloc(sizeof(DB_C_TXN_LIST), GFP_KERNEL);
	(*c_txn_list)->c_txn_ptr = c_txn;
	INIT_LIST_HEAD(&((*c_txn_list)->c_txn_list));
}

static inline void c_txn_list_free(DB_C_TXN_LIST *c_txn_list)
{
	kfree(c_txn_list);
}

static inline int calc_txn_buf_size(DB_TXN_BUF *txn_buf)
{
	int total = 0;
	total += sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + txn_buf->key_len + sizeof(uint32_t) + sizeof(uint32_t) + PAGE_SIZE;
	// total = tid, type, key_len, key, val_off, val_len, val
	
	return total;
}

static inline int c_txn_is_available(DB_C_TXN *c_txn, DB_TXN *txn)
{
	return c_txn->size + txn->size > C_TXN_LIMIT_BYTES ? 0 : 1;
}

static inline int c_txn_available_bytes(DB_C_TXN *c_txn)
{
	return C_TXN_LIMIT_BYTES - c_txn->size;
}

static inline int diff_c_txn_and_txn(DB_C_TXN *c_txn, DB_TXN *txn)
{
	return C_TXN_LIMIT_BYTES - c_txn->size - txn->size;
}

static inline void txn_buf_setup(DB_TXN_BUF *txn_buf, const void *data, uint32_t off, uint32_t size, enum lightfs_req_type type)
{
	char data_buf = (char *)data;
	txn_buf->off = off;
	txn_buf->len = size;
	txn_buf->next = NULL;

	// TODO
	switch (type) {
		case LIGHTFS_GET:
			txn_buf->buf = data;
			break;
		case LIGHTFS_SET:
			memcpy(txn_buf->buf+off, data_buf+off, size);
			break;
		default:
	}
}

static inline void alloc_txn_buf_key_from_dbt(DB_TXN_BUF *txn_buf, DBT *dbt)
{
	txn_buf->key = kmalloc(dbt->size, GFP_KERNEL);
	memcpy(txn_buf->key, dbt->data, dbt->size);
	txn_buf->key_len = dbt_size;
}


static inline uint32_t copy_dbt_from_dbc(DBC *dbc, DBT *dbt)
{
	dbt->size = *((uint32_t *)(dbc->buf + dbc->idx);
	memcpy(dbt->data, dbc->buf + dbc->idx + sizeof(uint32_t), dbt->size);
	
	return sizeof(uint32_t) + dbt->size;
}

int lightfs_bstore_txn_begin(DB_TXN *, DB_TXN **, uint32_t);
int lightfs_bstore_txn_commit(DB_TXN *, uint32_t);
int lightfs_bstore_txn_abort(DB_TXN *);
int init_lightfs_txn_hdlr(void);

#endif
