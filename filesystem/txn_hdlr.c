#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>

#include "txn_hdlr.h"

static struct kmem_cache *lightfs_c_txn_cachep;
static struct kmem_cache *lightfs_txn_cachep;
static struct kmem_cache *lightfs_txn_buf_cachep;

static struct __lightfs_txn_hdlr *txn_hdlr;

static void lightfs_c_txn_init_once(void *c_txn)
{
	struct DB_C_TXN *_c_txn = c_txn;
	INIT_LIST_HEAD(&_c_txn->c_txn_list);
	INIT_LIST_HEAD(&_c_txn->txn_list);
	INIT_LIST_HEAD(&_c_txn->children);
	_c_txn->size = 0;
	_c_txn->filter = (struct bloomfilter *)kmalloc(sizeof(struct bloomfilter) + C_TXN_BLOOM_M_BYTES, GFP_KERNEL);
	_c_txn->state = TXN_CREATED;
	_c_txn->parents = 0;
	_c_txn->children_num = 0;
	bloomfilter_init(_c_txn->filter, C_TXN_BLOOM_M_BYTES * 8, BLOOM_K);
}

static void lightfs_c_txn_free(DB_C_TXN *c_txn)
{
	kfree(_c_txn->filter);
	kmem_cache_free(lightfs_c_txn_cachep, c_txn);
}


static void lightfs_txn_init_once(void *txn)
{
	struct DB_TXN *_txn= txn;
	INIT_LIST_HEAD(&_txn->txn_list);
	INIT_LIST_HEAD(&_txn->txn_buf_list);
	_txn->cnt = 0;
	_txn->size = sizeof(txn->cnt) + sizeof(txn->size); // txn->cnt, txn->size
	_txn->state = TXN_CREATED;
	// size = cnt + tnx_buf * cnt
}

static void lightfs_txn_free(DB_TXN *txn) {
	kmem_cache_free(lightfs_txn_cachep, txn);
}

static void lightfs_txn_buf_init_once(void *txn_buf)
{
	struct DB_TXN_BUF *_txn_buf = txn_buf;
	INIT_LIST_HEAD(&_txn_buf->txn_buf_list);
}

static void lightfs_txn_free(DB_TXN_BUF *txn_buf) {
	kmem_cache_free(lightfs_txn_buf_cachep, txn_buf);
}

void alloc_txn_buf_key_from_dbt(DB_TXN_BUF *txn_buf, DBT *dbt)
{
	txn_buf->key = kmalloc(dbt->size, GFP_KERNEL);
	memcpy(txn_buf->key, dbt->data, dbt->size);
	txn_buf->key_len = dbt_size;
}

int lightfs_bstore_txn_begin(DB_TXN *parent, DB_TXN **txn, uint32_t flags)
{
	unsigned long irqflags;

	while (txn_hdlr->txn_cnt >= TXN_LIMIT) {
		spin_lock_irqsave(&txn_hdlr->txn_hdlr_spin, irqflags);
		txn_hdlr->state = true;
		wake_up_interruptible(txn_hdlr->wq);
		spin_unlock_irqsqve(&txn_hdlr->txn_hdlr_spin, irqflags);
		msleep_interruptible(1000);
		printk(KERN_ERR "LIGHTFS ERROR: touch TXN_LIMIT.\n");
	}
	*txn = kmem_cache_alloc(lightfs_txn_cachep, GFP_KERNEL);
	// lightfs_txn_init_once
	
	spin_lock(&txn_hdlr->txn_list)
	list_add_tail(&((*txn)->txn_list), &txn_hdlr->txn_list);
	txn_hdlr->txn_cnt++;
	spin_unlock(&txn_hdlr->txn_list)

	return 0;
}

int lightfs_bstore_txn_insert(DB_TXN *txn, DBT *key, DBT *value, uint32_t off, uint32_t flags)
{
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	// lightfs_txn_buf_init_once
	txn_buf_setup(txn_buf, value->data, off, value->size);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

	txn->cnt++;
	txn->size += calc_txn_buf_size(txn_buf);
	list_add_tail(&txn_buf->txn_buf_list, &txn->txn_buf_list);
	txn->state = TXN_INSERTING;

	return 0;
}

int lightfs_bstore_txn_remove(DB_TXN *txn)
{
	return 0;
}

int lightfs_bstore_txn_commit(DB_TXN *txn, uint32_t flags)
{
	txn->state = TXN_COMMITTED;
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

static int lightfs_c_txn_create(DB_C_TXN **c_txn, enum lightfs_c_txn_state c_txn_state)
{
	*c_txn = kmem_cache_alloc(lightfs_c_txn_cachep, GFP_KERNEL);

	if (c_txn_state == C_TXN_ORDERED) {
		spin_lock(&txn_hdlr->ordered_c_txn_list)
		list_add_tail(&((*c_txn)->list), &txn_hdlr->ordered_c_txn_list);
		txn_hdlr->ordered_c_txn_cnt++;
		spin_unlock(&txn_hdlr->ordered_c_txn_list)
	} else {
		spin_lock(&txn_hdlr->orderless_c_txn_list)
		list_add_tail(&((*c_txn)->list), &txn_hdlr->orderless_c_txn_list);
		txn_hdlr->orderless_c_txn_cnt++;
		spin_unlock(&txn_hdlr->orderless_c_txn_list)
	}

	//TODO:: threshold

	return 0;
}

static int lightfs_c_txn_insert(DB_C_TXN *c_txn, DB_TXN *txn)
{
	DB_TXN_BUF *txn_buf;

	list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
		bloomfilter_set(c_txn->filter, txn_buf->key, txn_buf->key_len);
	}
	list_splice_tail(&txn->txn_list, &c_txn->txn_list);
	c_txn->size += txn->size;
	c_txn->state = TXN_INSERTING;

	return 0;
}

static int lightfs_c_txn_make_relation(DB_C_TXN *existing_c_txn, DB_C_TXN *c_txn)
{
	DB_C_TXN_LIST *child;
	c_txn_list_alloc(&child, c_txn);
	c_txn->parents++;
	list_add_tail(&child->c_txn_list, &existing_c_txn->children);
	existing_c_txn->children_num++;

	return 0;
}

static int lightfs_c_txn_transfer(DB_C_TXN *c_txn)
{
	//TODO: send c_txn & add 
	c_txn->state = TXN_TRANSFERING;
}

static int lightfs_c_txn_commit(DB_C_TXN *c_txn)
{
	//TODO: send commit
}

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
		diff = diff_c_txn_and_txn(c_txn, txn);
		if ((c_txn->state != TXN_TRANSFERING) && (diff >= 0) && (best_diff > diff)) {
			best_c_txn = c_txn; // the file that is able to be merged
		}
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			if ((c_txn->state != TXN_TRANSFERING) && (bloomfilter_get(c_txn->filter, txn_buf->key, txn_buf->key_len))) {
				//relations++;
				target_c_txn = c_txn; // related file
				ret = C_TXN_ORDERED;
				goto out;
			}
		}
	}

	best_diff = C_TXN_LIMIT_BYTES + 1;
	best_c_txn = NULL;
	list_for_each_entry_reverse(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
		diff = diff_c_txn_and_txn(c_txn, txn);
		if ((c_txn->state != TXN_TRANSFERING) && (diff >= 0) && (best_diff > diff)) {
			best_c_txn = c_txn;
		}
		list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
			if ((c_txn->state != TXN_TRANSFERING) && (bloomfilter_get(c_txn->filter, txn_buf->key, txn_buf->key_len))) {
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

static bool lightfs_txn_hdlr_check_state(void)
{
	bool ret;
	spin_lock(&txn_hdlr->txn_hdlr_spin);
	ret = txn_hdlr->state;
	spin_unlock(&txn_hdlr->txn_hdlr_spin);
	return ret;
}

// TODO:: READ????
int lightfs_txn_hdlr_run(void *data)
{
	struct DB_C_TXN *merge_c_txn, *related_c_txn, *c_txn, transfering_c_txn;
	struct DB_TXN *txn;
	enum lightfs_c_txn_state c_txn_state; 
	int diff, best_diff = C_TXN_LIMIT_BYTES + 1;

	while (1) {
		if (kthread_should_stop()) {
			break;
		}

		spin_lock(&txn_hdlr->txn_spin);
		if (!txn_hdlr->txn_cnt) {
			spin_unlock(&txn_hdlr->txn_spin);
			goto wait_on_txn;
		}
		spin_unlock(&txn_hdlr->txn_spin);

		txn = list_first_entry(&txn_hdlr->txn_list, DB_TXN, txn_list);
		if (txn->state != TXN_COMMITTED) {
			goto wait_on_txn;
		}

		//lightfs_c_txn_begin(&c_txn);

		list_for_each_entry(txn, &txn_hdlr->txn_list, txn_list) {
			c_txn_state = lightfs_txn_calc_order(txn, &merge_c_txn, &related_c_txn);
			if (merge_c_txn) {
				lightfs_c_txn_insert(merge_c_txn, txn);

			} else {
				lightfs_c_txn_create(&c_txn, c_txn_state);
				lightfs_c_txn_insert(c_txn, txn);
				lightfs_c_txn_make_relation(related_c_txn, txn);
			}
		}

		// may sleep thread, if transfering txn is full
		while (txn_hdlr->transfering_c_txn_cnt >= C_TXN_COMMITTING_LIMIT) {
			// transfer a txn that have most children
			list_for_each_entry(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
				if (c_txn->state != TXN_TRANSFERING) {
					lightfs_c_txn_transfer(c_txn);
				}
			}
		}
		
wait_on_txn:
		wait_event_interruptible_timeout(txn_hdlr->wq, kthread_should_stop() || lightfs_txn_hdlr_check_state(), msecs_to_jiffies(5000);

		spin_lock(&txn_hdlr->txn_hdlr_spin);
		txn_hdlr->state = false;
		spin_unlock(&txn_hdlr->txn_hdlr_spin);
	}
}


int lightfs_txn_hdlr_init(void)
{
	int ret;

	txn_hdlr = (struct __lightfs_txn_hdlr *)kmalloc(sizeof(struct __lightfs_txn_hdlr), GFP_KERNEL);
	if (!txn_hdlr) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize txn hdlr.\n");
		ret = -ENOMEM;
		goto out;
	}
	txn_hdlr->txn_cnt = 0;
	txn_hdlr->ordered_c_txn_count = 0;
	txn_hdlr->orderless_c_txn_count = 0;
	txn_hdlr->transfering_c_txn_count = 0;
	init_waitqueue_head(&txn_hdlr->wq);
	INIT_LIST_HEAD(&txn_hdlr->txn_list);
	INIT_LIST_HEAD(&txn_hdlr->ordered_c_txn_list);
	INIT_LIST_HEAD(&txn_hdlr->orderless_c_txn_list);
	spin_lock_init(&txn_hdlr->txn_hdlr_spin);
	spin_lock_init(&txn_hdlr->txn_spin);
	spin_lock_init(&txn_hdlr->ordered_c_txn_spin);
	spin_lock_init(&txn_hdlr->orderless_c_txn_spin);
	txn_hdlr->state = false;

	lightfs_c_txn_cachep = kmem_cache_create("lightfs_c_txn", sizeof(DB_C_TXN), 0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, lightfs_c_txn_init_once);

	if (!lightfs_c_txn_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize c txn cache.\n");
		ret = -ENOMEM;
		goto out_free_c_txn_cachep;
	}


	lightfs_txn_cachep = kmem_cache_create("lightfs_txn", sizeof(DB_TXN), 0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, lightfs_txn_init_once);

	if (!lightfs_txn_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize txn cache.\n");
		ret = -ENOMEM;
		goto out_free_txn_cachep;
	}

	lightfs_txn_buf_cachep = kmem_cache_create("lightfs_txn_buf", sizeof(DB_TXN_BUF), 0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, light_txn_buf_init_once);

	if (!lightfs_txn_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize txn buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_txn_buf_cachep;
	}

	txn_hdlr->tsk = (struct task_struct *)kthread_run(lightfs_txn_hdlr_run, NULL, "lightfs_txn_hdlr");

	return 0;

out_free_txn_buf_cachep:
	kmem_cache_destroy(lightfs_txn_buf_cachep);
out_free_txn_cachep:
	kmem_cache_destroy(lightfs_txn_cachep);
out_free_c_txn_cachep:
	kmem_cache_destroy(lightfs_c_txn_cachep);
out:
	return ret;
}

