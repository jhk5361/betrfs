#ifndef __LIGHTFS_H__
#define __LIGHTFS_H__

#include "ftfs_fs.h"


typedef struct __lightfs_db_io DB_IO;
typedef struct __lightfs_txn_buffer DB_TXN_BUF;
typedef struct __lightfs_c_txn DB_C_TXN;
typedef struct __lightfs_c_txn_list DB_C_TXN_LIST;

struct __lightfs_txn_buffer {
	uint32_t txn_id;
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
	DB *db;
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
};

struct __lightfs_c_txn_list {
	DB_C_TXN *c_txn_ptr;
	struct list_head c_txn_list;
};

struct __lightfs_db_io {
	int (*get) (DB *db, DB_TXN_BUF *txn_buf);
	int (*iter) (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf);
	int (*transfer) (DB *db, DB_C_TXN *c_txn);
	int (*commit) (DB_C_TXN *c_txn);
	int (*close) (DB_IO *db_io);
};

struct __lightfs_txn_hdlr {
	struct task_struct *tsk;
	wait_queue_head_t wq;
	wait_queue_head_t txn_wq;
	uint32_t txn_id;
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
	DB_IO *db_io;
};




#endif
