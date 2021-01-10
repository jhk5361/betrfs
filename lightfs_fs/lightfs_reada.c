#include "ftfs_fs.h"
#include "lightfs_reada.h"
#include "./cheeze/cheeze.h"
#include "lightfs.h"

struct reada_entry *lightfs_reada_alloc(struct inode *inode, uint64_t current_block_num, unsigned block_cnt) {
	struct reada_entry *ra_entry = kmalloc(sizeof(struct reada_entry), GFP_KERNEL);
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);

	//BUG_ON(ra_entry->reada_state & READA_FULL);

	ra_entry->reada_state = READA_FULL;
	ra_entry->reada_block_start = current_block_num;
	ra_entry->reada_block_len = block_cnt;
	ra_entry->tag = 0;
	init_completion(&ra_entry->reada_acked);
	ra_entry->extra = ftfs_inode;

	INIT_LIST_HEAD(&ra_entry->list);
	//spin_lock(&ftfs_inode->reada_spin);
	list_add_tail(&ra_entry->list, &ftfs_inode->ra_list);
	ftfs_inode->ra_entry_cnt++;
	if (ftfs_inode->ra_entry_cnt == 1) {
		BUG_ON(ftfs_inode->ra_entry);
		ftfs_inode->ra_entry = ra_entry;
	}
	//spin_unlock(&ftfs_inode->reada_spin);
	//spin_lock_init(&ra_entry->reada_spin);

	return ra_entry;
}

void lightfs_reada_free(struct reada_entry *ra_entry, struct inode *inode) {
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	struct reada_entry *tmp;
	//BUG_ON(!(ra_entry->reada_state & READA_DONE));
	spin_lock(&ftfs_inode->reada_spin);
	if (!(ra_entry->reada_state & READA_DONE)) {
		spin_unlock(&ftfs_inode->reada_spin);
		wait_for_completion(&ra_entry->reada_acked);
		spin_lock(&ftfs_inode->reada_spin);
	}
	//ftfs_inode->reada_state = READA_EMPTY;
	cheeze_free_io(ftfs_inode->ra_entry->tag);
	list_del(&ra_entry->list);
	//tmp = ftfs_inode->ra_entry;
	//ftfs_inode->ra_entry = NULL;
	ftfs_inode->ra_entry_cnt--;
	if (ftfs_inode->ra_entry_cnt == 0) {
		ftfs_inode->ra_entry = NULL;
	} else {
		ftfs_inode->ra_entry = list_first_entry(&ftfs_inode->ra_list, struct reada_entry, list);
	}
	spin_unlock(&ftfs_inode->reada_spin);
	kfree(tmp);
}

void lightfs_reada_all_flush(struct inode *inode) {
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	struct reada_entry *ra_entry, *next;

	list_for_each_entry_safe(ra_entry, next, &ftfs_inode->ra_list, list) {
		lightfs_reada_free(ra_entry, inode);
	}
}

void lightfs_reada_flush(struct inode *inode, int cnt) {
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	struct reada_entry *ra_entry, *next;
	volatile int i = 0;

	list_for_each_entry_safe(ra_entry, next, &ftfs_inode->ra_list, list) {
		if (cnt == i)
			break;
		lightfs_reada_free(ra_entry, inode);
		i++;
	}
}


struct reada_entry *lightfs_reada_reuse(struct inode *inode, uint64_t current_block_num, unsigned block_cnt) {
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	struct reada_entry *ra_entry = ftfs_inode->ra_entry;

	//BUG_ON(ftfs_inode->reada_state & READA_EMPTY);

	cheeze_free_io(ra_entry->tag);

	ra_entry->reada_state = READA_FULL;
	ra_entry->reada_block_start = current_block_num;
	ra_entry->reada_block_len = block_cnt;
	ra_entry->tag = 0;
	reinit_completion(&ra_entry->reada_acked);
	ra_entry->extra = ftfs_inode;

	spin_lock(&ftfs_inode->reada_spin);
	list_move_tail(&ra_entry->list, &ftfs_inode->ra_list);
	spin_unlock(&ftfs_inode->reada_spin);

	//spin_lock_init(&ra_entry->reada_spin);

	return ra_entry;
}


bool lightfs_reada_need(struct inode *inode, struct ftio *ftio, unsigned nr_pages, bool fg_read) {
	uint64_t current_start_block;
	bool ret = false;
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);

	if (nr_pages < READA_THRESHOLD) {
		return false;
	}


	current_start_block = PAGE_TO_BLOCK_NUM(ftio_first_page(ftio));

	spin_lock(&ftfs_inode->reada_spin);
	if (ftfs_inode->ra_entry_cnt >= READA_QD) {
		ret = false;
	} else {
		if (fg_read) {
			if(current_start_block == ftfs_inode->last_block_start + ftfs_inode->last_block_len) {
				ret = true;
			}
		} else if (ftfs_inode->ra_entry) {
			if (current_start_block + nr_pages == ftfs_inode->ra_entry->reada_block_start + ftfs_inode->ra_entry->reada_block_len) {
				ret = true;
			}
		}
	}
	ftfs_inode->last_block_start = current_start_block;
	ftfs_inode->last_block_len = nr_pages;
	spin_unlock(&ftfs_inode->reada_spin);
	return ret;
}

static bool lightfs_reada_wait_finished(struct inode *inode) {
	bool ret;
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	spin_lock(&ftfs_inode->reada_spin);
	ret = ftfs_inode->ra_entry->reada_state & READA_DONE;
	spin_unlock(&ftfs_inode->reada_spin);
	return ret;
}

unsigned lightfs_reada_buffer_get(struct reada_entry *ra_entry, struct inode *inode, struct ftio *ftio, unsigned nr_pages) {
	unsigned ret;
	unsigned processed_pages = 0;
	uint64_t current_block_num, block_cnt;
	struct page *page;
	char *page_buf;
	int idx;
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	//struct reada_entry *ra_entry = ftfs_inode->ra_entry;
	
	if (!ftfs_inode->ra_entry) {
		ret = ENORA;
		goto out;
	}

	if (nr_pages < READA_THRESHOLD) {
		ret = ESMALL;
		goto out;
	}


	spin_lock(&ftfs_inode->reada_spin);
	if (ra_entry->reada_state & READA_EMPTY || nr_pages < READA_THRESHOLD) {
		spin_unlock(&ftfs_inode->reada_spin);
		ret = ENORA;
		goto out;
	}

	current_block_num = PAGE_TO_BLOCK_NUM(ftio_current_page(ftio));
	if (current_block_num >=  ra_entry->reada_block_start) {
		idx = current_block_num - ra_entry->reada_block_start;
		if (current_block_num + nr_pages <= ra_entry->reada_block_start + ra_entry->reada_block_len) { // buf is enough to serve requests
			if (!(ra_entry->reada_state & READA_DONE)) {
				spin_unlock(&ftfs_inode->reada_spin);
				wait_for_completion(&ra_entry->reada_acked);
				spin_lock(&ftfs_inode->reada_spin);
			}
			BUG_ON(!(ra_entry->reada_state & READA_DONE));
			while (!ftio_job_done(ftio)) {
				page = ftio_current_page(ftio);
				page_buf = kmap_atomic(page);
				memcpy(page_buf, ra_entry->buf + idx, PAGE_SIZE);
				kunmap_atomic(page_buf);
				ftio_advance_page(ftio);
				idx++;
				processed_pages++;
			}
		} else if (current_block_num < ra_entry->reada_block_start + ra_entry->reada_block_len) { // buf is not enough
			if (!(ra_entry->reada_state & READA_DONE)) {
				spin_unlock(&ftfs_inode->reada_spin);
				wait_for_completion(&ra_entry->reada_acked);
				spin_lock(&ftfs_inode->reada_spin);
			}
			BUG_ON(!(ra_entry->reada_state & READA_DONE));
			while(idx < ra_entry->reada_block_len) {
				page = ftio_current_page(ftio);
				page_buf = kmap_atomic(page);
				memcpy(page_buf, ra_entry->buf + idx, PAGE_SIZE);
				kunmap_atomic(page_buf);
				ftio_advance_page(ftio);
				idx++;
				processed_pages++;
			}
		} else { // buffer miss
			processed_pages = 0;
		}
	} else { // buffer miss
		processed_pages = 0;
	}
	ret = processed_pages;
	spin_unlock(&ftfs_inode->reada_spin);
out:
	return ret;
}
