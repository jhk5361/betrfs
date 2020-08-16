#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>
#include "lightfs_io.h"
#include "lightfs_txn_hdlr.h"
#include "rbtreekv.h"

int lightfs_io_get (DB *db, DB_TXN_BUF *txn_buf)
{
	return 0;
}

int lightfs_io_iter (DB *db, DBC *dbc, DB_TXN_BUF *txn_buf)
{
	return 0;
}

int lightfs_io_transfer (DB *db, DB_C_TXN *c_txn)
{
	return 0;
}

int lightfs_io_commit (DB_C_TXN *c_txn)
{
	return 0;
}

int lightfs_io_close (DB_IO *db_io)
{
	kfree(db_io);
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

int rb_io_transfer (DB *db, DB_C_TXN *c_txn)
{
	DBT key, value;
	DB_TXN_BUF *txn_buf;
	DB_TXN *txn;

	list_for_each_entry(txn, &c_txn->txn_list, txn_list) {
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			dbt_setup(&key, txn_buf->key, txn_buf->key_len);
			dbt_setup(&value, txn_buf->buf+txn_buf->off, txn_buf->len);

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
					db_update(txn_buf->db, NULL, &key, &value, txn_buf->off, 0);
					break;
				default:
					break;
			}
		}
	}
	
	return 0;
}

int rb_io_commit (DB_C_TXN *c_txn)
{
	return 0;
}

int rb_io_close (DB_IO *db_io)
{
	kfree(db_io);
	return 0;
}

int lightfs_io_create (DB_IO **db_io) {
	(*db_io) = (DB_IO *)kmalloc(sizeof(DB_IO), GFP_KERNEL);
#ifdef EMULATION
	(*db_io)->get = rb_io_get;
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
	return 0;
}

