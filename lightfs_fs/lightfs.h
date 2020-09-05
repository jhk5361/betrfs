#ifndef __LIGHTFS_H__
#define __LIGHTFS_H__

#include "ftfs_fs.h"

#define LIGHTFS_TXN_LIMIT 384
#define UINT16_MAX (65535U)
#define LIGHTFS_IO_LARGE_BUF (2 * 1024 * 1024 + 200 * 1024)
#define LIGHTFS_IO_SMALL_BUF (4 * 1024)


typedef struct __lightfs_db_io DB_IO;
typedef struct __lightfs_txn_buffer DB_TXN_BUF;
typedef struct __lightfs_c_txn DB_C_TXN;
typedef struct __lightfs_c_txn_list DB_C_TXN_LIST;
typedef uint32_t TXNID_T;

struct __lightfs_txn_buffer {
	TXNID_T txn_id;
	struct list_head txn_buf_list;
	char *key;
	uint16_t key_len;
	uint16_t off;
	uint16_t len;
	uint16_t update;
	uint32_t tid;
	enum lightfs_req_type type;
	//char buf[PAGE_SIZE];
	//struct completion *completionp;
	char *buf;
	//void * (*txn_buf_cb)(void *data);
	uint32_t ret;
	DB *db;
};

struct __lightfs_c_txn {
	TXNID_T txn_id;
	struct list_head c_txn_list;
	struct list_head txn_list;
	struct list_head children;
	uint32_t size;
	uint16_t parents;
	//enum lightfs_txn_state state;
	uint32_t state;
	struct bloomfilter *filter;
};

struct __lightfs_c_txn_list {
	DB_C_TXN *c_txn_ptr;
	struct list_head c_txn_list;
};

struct __lightfs_db_io {
	int (*get) (DB *db, DB_TXN_BUF *txn_buf);
	int (*sync_put) (DB *db, DB_TXN_BUF *txn_buf);
	int (*iter) (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf);
	int (*transfer) (DB *db, DB_C_TXN *c_txn);
	int (*commit) (DB_TXN_BUF *txn_buf);
	int (*close) (DB_IO *db_io);
};

struct __lightfs_txn_hdlr {
	struct task_struct *tsk;
	wait_queue_head_t wq;
	wait_queue_head_t txn_wq;
	TXNID_T txn_id;
	uint32_t txn_cnt;
	uint32_t ordered_c_txn_cnt;
	uint32_t orderless_c_txn_cnt;
	uint32_t committing_c_txn_cnt;
	uint32_t running_c_txn_cnt;
	uint64_t running_c_txn_id;
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
	spinlock_t running_c_txn_spin;
	DB_IO *db_io;
	DB_C_TXN *running_c_txn;
	DB_C_TXN *committing_c_txn;
};




#endif
