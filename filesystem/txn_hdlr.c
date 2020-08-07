#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/completion.h>

#include "txn_hdlr.h"

//TODO: read/tid/type/transfer

static struct kmem_cache *lightfs_c_txn_cachep;
static struct kmem_cache *lightfs_txn_cachep;
static struct kmem_cache *lightfs_txn_buf_cachep;
static struct kmem_cache *lightfs_buf_cachep;
static struct kmem_cache *lightfs_completion_cachep;

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
	bloomfilter_init(_c_txn->filter, C_TXN_BLOOM_M_BYTES * 8, BLOOM_K);
}

static void lightfs_c_txn_free(DB_C_TXN *c_txn)
{
	kfree(c_txn->filter);
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
	//txn_buf->buf = NULL;
	INIT_LIST_HEAD(&_txn_buf->txn_buf_list);
}

static void lightfs_txn_buf_free(DB_TXN_BUF *txn_buf) {
	kfree(txn_buf->key);
	kmem_cache_free(lightfs_txn_buf_cachep, txn_buf);
}

static void lightfs_completion_init_once(void *completionp)
{
	//struct completion *completionp = (struct completion *)_completion;
	init_completion((struct completion *)completionp);
}

static void lightfs_completion_free(struct completion *completionp)
{
	kmem_cache_free(lightfs_completion_cachep, completionp);
}

static bool lightfs_bstore_txn_check()
{
	unsigned long irqflags;
	bool ret;
	spin_lock_irqsave(&txn_hdlr->txn_spin, irqflags);
	if (txn_hdlr->txn_cnt < TXN_LIMIT) {
		ret = true;
	} else {
		ret = false;
	}
	spin_unlock_irqstore(&txn_hdlr->txn_spin, irqflags);
	return ret;
}

int lightfs_bstore_txn_begin(DB_TXN *parent, DB_TXN **txn, uint32_t flags)
{
	unsigned long irqflags;

	if (txn_hdlr->txn_cnt >= TXN_LIMIT) {
		spin_lock_irqsave(&txn_hdlr->txn_hdlr_spin, irqflags);
		if (waitqueue_active(&txn_hdlr->wq)) {
			if (txn_hdlr->contention == false) {
				wake_up_interruptible(&txn_hdlr->wq);
				txn_hdlr->contention = true;
				txn_hdlr->state = true;
			}
		}
		spin_unlock_irqstore(&txn_hdlr->txn_hdlr_spin, irqflags);
		wake_event_interruptible(&txn_hdlr->txn_wq, lightfs_bstore_txn_check());
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

int lightfs_bstore_txn_get(DB_TXN *txn, DBT *key, DBT *value, uint32_t off, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	txn_buf->completionp = kmem_cache_alloc(lightfs_completion_cachep, GFP_KERNEL);
	//txn_buf->buf = kmem_cache_alloc(lightfs_buf_cachep, GFP_KERNEL);
	txn_buf_setup(txn_buf, value->data, off, value->size, type);
	alloc_txn_buf_from_dbt(txn_buf, key);

	lightfs_bstore_txn_buf_read(txn_buf);

	wait_for_completion(txn_buf->completionp);

	lightfs_completion_free(txn_buf->completionp);
	lightfs_txn_buf_free(txn_buf);

	return 0;
}

void *lightfs_bstore_txn_get_cb(void *completion)
{
	completion(completion);
	return NULL;
}

int lightfs_bstore_txn_insert(DB_TXN *txn, DBT *key, DBT *value, uint32_t off, enum lightfs_req_type type)
{
	DB_TXN_BUF *txn_buf;

	txn_buf = kmem_cache_alloc(lightfs_txn_buf_cachep, GFP_KERNEL);
	txn_buf->buf = (char*)kmem_cache_alooc(lightfs_buf_cachep, GFP_KERNEL);
	// lightfs_txn_buf_init_once
	txn_buf_setup(txn_buf, value->data, off, value->size, type);
	alloc_txn_buf_key_from_dbt(txn_buf, key);

	txn->cnt++;
	txn->size += calc_txn_buf_size(txn_buf);
	list_add_tail(&txn_buf->txn_buf_list, &txn->txn_buf_list);
	//txn->state = TXN_INSERTING;

	return 0;
}

int lightfs_bstore_txn_remove(DB_TXN *txn)
{
	//spin_lock(&txn_hdlr->txn_list);
	//spin_unlock(&txn_hdlr->txn_list);
	return 0;
}

int lightfs_bstore_txn_commit(DB_TXN *txn, uint32_t flags)
{
	//smp_mb();
	//TODO:: is it necessary?
	spin_lock(&txn_hdlr->txn_spin);
	txn->state = TXN_COMMITTED;
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

static int lightfs_c_txn_create(DB_C_TXN **c_txn, enum lightfs_c_txn_state c_txn_state)
{
	*c_txn = kmem_cache_alloc(lightfs_c_txn_cachep, GFP_KERNEL);

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
		list_del(&c_txn->c_txn_list, &txn_hdlr->ordered_c_txn_list);
		txn_hdlr->ordered_c_txn_cnt--;
	} else {
		list_del(&c_txn->c_txn_list, &txn_hdlr->orderless_c_txn_list);
		txn_hdlr->orderless_c_txn_cnt--;
	}

	while (!list_empty(&c_txn->txn_list)) {
		txn = list_first_entry(&c_txn->txn_list, DB_TXN, txn_list);
		while(!list_empty(&txn->txn_buf_list)) {
			txn_buf = list_first_entry(&txn->txn_buf_list, DB_TXN_BUF, txn_buf_list);
			list_del(&txn_buf->txn_buf_list);
			kmem_cache_free(lightfs_buf_cachep, txn_buf->buf); //TODO
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

	list_for_each_entry(txn_buf, &txn->txn_buf_list, txn_buf_list) {
		bloomfilter_set(c_txn->filter, txn_buf->key, txn_buf->key_len);
	}
	spin_lock(&txn_hdlr->txn_spin);
	list_move_tail(&txn->txn_list, &c_txn->txn_list);
	txn_hdlr->txn_cnt--;
	spin_unlock(&txn_hdlr->txn_spin);
	c_txn->size += txn->size;
	//c_txn->state = TXN_INSERTING;

	return 0;
}

static int lightfs_c_txn_make_relation(DB_C_TXN *existing_c_txn, DB_C_TXN *c_txn)
{
	DB_C_TXN_LIST *child;
	c_txn_list_alloc(&child, c_txn);
	c_txn->parents++;
	list_add_tail(&child->c_txn_list, &existing_c_txn->children);

	return 0;
}

static int lightfs_c_txn_transfer(DB_C_TXN *c_txn)
{
	//TODO: send c_txn & add 
	//
	txn_hdlr->committing_c_txn_cnt++
	c_txn->state = TXN_TRANSFERING;

	return 0;
}

static void* lightfs_c_txn_transfer_cb(void *data) {
	DB_C_TXN_LIST *committed_c_txn_list;
	DB_C_TXN *c_txn = (DB_C_TXN *)data;

	c_txn_list_alloc(&committed_c_txn_list, c_txn);
	spin_lock(&txn_hdlr->committed_c_txn_spin);
	list_add_tail(&child->c_txn_list, &txn_hdlr->committed_c_txn_list);
	spin_unlock(&txn_hdlr->committed_c_txn_spin);

	return NULL;
}

static int lightfs_c_txn_commit(DB_C_TXN *c_txn)
{
	DB_C_TXN_LIST *child;
	DB_C_TXN *child_c_txn;

	while (!list_empty(&c_txn->children)) {
		child = list_first_entry(&c_txn->children, DB_C_TXN_LIST, c_txn_list);
		child_c_txn = child->c_txn_ptr;
		child_c_txn->parents--;
		if (!child_c_txn->parent) {
			list_move_tail(&child_c_txn->c_txn_list, &txn_hdlr->orderless_c_txn_list);
			txn_hdlr->orderless_c_txn_cnt++;
			txn_hdlr->ordered_c_txn_cnt--;
		}
		list_del(&child->c_txn_list);
		c_txn_list_free(child);
	}
	lightfs_c_txn_destroy(c_txn, C_TXN_ORDERLESS);

	return 0;
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
	DB_C_TXN *merge_c_txn, *related_c_txn, *c_txn, transfering_c_txn;
	DB_TXN *txn;
	DB_C_TXN_LIST *committed_c_txn_list;
	enum lightfs_c_txn_state c_txn_state; 
	int diff, best_diff = C_TXN_LIMIT_BYTES + 1;

	while (1) {
		if (kthread_should_stop()) {
			break;
		}

commit_repeat:
		spin_lock(&txn_hdlr->committed_spin_lock);
		if (list_empty(&txn_hdlr->txn_list)) {
			spin_unlock(&txn_hdlr->txn_spin);
			goto txn_repeat;
		}
		committed_c_txn_list = list_first_entry(&txn_hdlr->committed_c_txn_list, DB_C_TXN, c_txn_list);
		list_del(&committed_c_txn_list->c_txn_list);
		spin_unlock(&txn_hdlr->committed_spin_lock);
		c_txn = c_txn_list->c_txn_ptr;
		lightfs_c_txn_commit(c_txn);

txn_repeat:
		spin_lock(&txn_hdlr->txn_spin);
		if (waitqueue_active(&txn_hdlr->txn_wq) && txn_hdlr->txn_cnt <= TXN_THRESHOLD) {
			wake_up_all(&txn_wq);
		}
		if (list_empty(&txn_hdlr->txn_list)) {
			spin_unlock(&txn_hdlr->txn_spin);
			goto transfer;
		}
		txn = list_first_entry(&txn_hdlr->txn_list, DB_TXN, txn_list);
		if (txn->state != TXN_COMMITTED) {
			spin_unlock(&txn_hdlr->txn_spin);
			goto transfer;
		}
		spin_unlock(&txn_hdlr->txn_spin);
		if (txn_hdlr->ordered_c_txn_cnt + txn_hdlr->orderless_c_txn_cnt >= C_TXN_LIMIT) {
			goto transfer;			
		}
		c_txn_state = lightfs_txn_calc_order(txn, &merge_c_txn, &related_c_txn);
		if (merge_c_txn) {
			lightfs_c_txn_insert(merge_c_txn, txn);
		} else {
			lightfs_c_txn_create(&c_txn, c_txn_state);
			lightfs_c_txn_insert(c_txn, txn);
			lightfs_c_txn_make_relation(related_c_txn, txn);
		}
		goto txn_repeat;

transfer:
		// may sleep thread, if transfering txn is full
			// transfer a txn that have most children
		list_for_each_entry(c_txn, &txn_hdlr->orderless_c_txn_list, c_txn_list) {
			if (c_txn->state != TXN_TRANSFERING) {
				lightfs_c_txn_transfer(c_txn);
			}
			if (txn_hdlr->committing_c_txn_cnt >= C_TXN_COMMITTING_LIMIT) {
				break;
			}
		}
		
wait_on_txn:
		//TODO
		wait_event_interruptible_timeout(&txn_hdlr->wq, kthread_should_stop() || lightfs_txn_hdlr_check_state(), msecs_to_jiffies(5000);

		spin_lock(&txn_hdlr->txn_hdlr_spin);
		txn_hdlr->state = false;
		spin_unlock(&txn_hdlr->txn_hdlr_spin);
	}
}


int lightfs_txn_hdlr_init(void)
{
	int ret;

	txn_hdlr_alloc(txn_hdlr);
	
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

	lightfs_buf_cachep = kmem_cache_create("lightfs_buf", PAGE_SIZE, 0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);

	if (!lightfs_buf_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_buf_cachep;
	}

	lightfs_completion_cachep = kmem_cache_create("lightfs_buf", sizeof(struct completion), 0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, lightfs_completion_init_once);

	if (!lightfs_completion_cachep) {
		printk(KERN_ERR "LIGHTFS ERROR: Failed to initialize buffer cache.\n");
		ret = -ENOMEM;
		goto out_free_completion_cachep;
	}



	txn_hdlr->tsk = (struct task_struct *)kthread_run(lightfs_txn_hdlr_run, NULL, "lightfs_txn_hdlr");

	return 0;

out_free_completion_cachep:
	kmem_cache_destroy(lightfs_completion_cachep);
out_free_buf_cachep:
	kmem_cache_destroy(lightfs_buf_cachep);
out_free_txn_buf_cachep:
	kmem_cache_destroy(lightfs_txn_buf_cachep);
out_free_txn_cachep:
	kmem_cache_destroy(lightfs_txn_cachep);
out_free_c_txn_cachep:
	kmem_cache_destroy(lightfs_c_txn_cachep);
out:
	return ret;
}

