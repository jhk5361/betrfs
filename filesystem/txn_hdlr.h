#ifndef __TXN_HDLR__
#define __TXN_HDLR__

#include <tokudb.h>
#include <list.h>
#include <linux/spinlock.h> 
#include "bloomfilter.h"

#define C_TXN_LIMIT_BYTES 2 * 1024 * 1024
#define C_TXN_BLOOM_M_BYTES 308 // 512 items, p=0.1
//#define C_TXN_BLOOM_M_BYTES 791 // 512 items, p=0.01
#define C_TXN_BLOOM_K 3
#define LIGHTFS_ORDER_MAX 3000000

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
	char buf[PAGE_SIZE];
};

struct __lightfs_c_txn {
	uint32_t tid;
	struct list_head c_txn_list;
	struct list_head txn_list;
	struct list_head children;
	uint32_t size;
	enum lightfs_txn_state state;
	struct bloomfilter *filter;
}

struct __lightfs_c_txn_list {
	DB_C_TXN *c_txn_ptr;
	struct list_head c_txn_list;
}

struct __lightfs_txn_hdlr {
	uint32_t txn_cnt;
	uint32_t ordered_c_txn_cnt;
	uint32_t orderless_c_txn_cnt;
	struct list_head txn_list;
	struct list_head ordered_c_txn_list;
	struct list_head orderless_c_txn_list;
	spinlock_t txn_spin;
	spinlock_t ordered_c_txn_spin;
	spinlock_t orderless_c_txn_spin;

};

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

static inline int diff_c_txn_and_txn(DB_C_TXN *c_txn, DB_TXN *txn)
{
	return C_TXN_LIMIT_BYTES - c_txn->size - txn->size;
}

static inline void txn_buf_setup(DB_TXN_BUF *txn_buf, const void *data, uint32_t off, uint32_t size)
{
	char data_buf = (char *)data_buf;
	memcpy(txn_buf->buf+off, data_buf+off, size);
	txn_buf->off = off;
	txn_buf->len = size;
	txn_buf->next = NULL;

	// TODO
	switch (flags) {
		case asd:
			txn_buf = DB_WRITE;
			break;
		default:
	}
}

int lightfs_bstore_txn_begin(DB_TXN *, DB_TXN **, uint32_t);
int lightfs_bstore_txn_commit(DB_TXN *, uint32_t);
int lightfs_bstore_txn_abort(DB_TXN *);
int init_lightfs_txn_hdlr(void);

#endif
