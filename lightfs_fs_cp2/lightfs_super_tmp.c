/* -*- mode: C++; c-basic-offset: 8; indent-tabs-mode: t -*- */
// vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab:

#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/parser.h>
#include <linux/list_sort.h>
#include <linux/writeback.h>
#include <linux/path.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/quotaops.h>

#include "ftfs_fs.h"
#include "lightfs.h"

static char root_meta_key[] = "m\x00\x00\x00\x00\x00\x00\x00\x00";

static struct kmem_cache *ftfs_inode_cachep;

/*
 * ftfs_i_init_once is passed to kmem_cache_create
 * Once an inode is allocated, this function is called to init that inode
 */
static void ftfs_i_init_once(void *inode)
{
	struct ftfs_inode *ftfs_inode = inode;

	dbt_init(&ftfs_inode->meta_dbt);

	inode_init_once(&ftfs_inode->vfs_inode);
}

static void
ftfs_setup_metadata(struct ftfs_metadata *meta, umode_t mode,
                    loff_t size, dev_t rdev, ino_t ino)
{
	struct timespec now_tspec;
	time_t now;

	now_tspec = current_kernel_time();
	TIMESPEC_TO_TIME_T(now, now_tspec);

	meta->type = FTFS_METADATA_TYPE_NORMAL;
	meta->u.st.st_dev = 0;
	meta->u.st.st_ino = ino;
	meta->u.st.st_mode = mode;
	meta->u.st.st_size = size;
	meta->u.st.st_nlink = 1;
#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
	meta->u.st.st_uid = current_uid().val;
	meta->u.st.st_gid = current_gid().val;
#else
	//meta->u.st.st_uid = current_uid();
	//meta->u.st.st_gid = current_gid();
	meta->u.st.st_uid = from_kuid_munged(current_user_ns(), current_uid());
	meta->u.st.st_gid = from_kgid_munged(current_user_ns(), current_gid());
#endif
	meta->u.st.st_rdev = rdev;
	meta->u.st.st_blocks = ftfs_get_block_num_by_size(size);
	meta->u.st.st_blksize = FTFS_BSTORE_BLOCKSIZE;
	meta->u.st.st_atime = now;
	meta->u.st.st_mtime = now;
	meta->u.st.st_ctime = now;
}

static void
ftfs_copy_metadata_from_inode(struct ftfs_metadata *meta, struct inode *inode)
{
	meta->type = FTFS_METADATA_TYPE_NORMAL;
	meta->u.st.st_dev = 0;
	meta->u.st.st_ino = inode->i_ino;
	meta->u.st.st_mode = inode->i_mode;
	meta->u.st.st_nlink = inode->i_nlink;
#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
	meta->u.st.st_uid = inode->i_uid.val;
	meta->u.st.st_gid = inode->i_gid.val;
#else
	//meta->u.st.st_uid = inode->i_uid;
	//meta->u.st.st_gid = inode->i_gid;
	meta->u.st.st_uid = from_kuid_munged(inode->i_sb->s_user_ns, inode->i_uid);
	meta->u.st.st_gid = from_kgid_munged(inode->i_sb->s_user_ns, inode->i_gid);
#endif
	meta->u.st.st_rdev = inode->i_rdev;
	meta->u.st.st_size = i_size_read(inode);
	meta->u.st.st_blocks = ftfs_get_block_num_by_size(meta->u.st.st_size);
	meta->u.st.st_blksize = FTFS_BSTORE_BLOCKSIZE;
	TIMESPEC_TO_TIME_T(meta->u.st.st_atime, inode->i_atime);
	TIMESPEC_TO_TIME_T(meta->u.st.st_mtime, inode->i_mtime);
	TIMESPEC_TO_TIME_T(meta->u.st.st_ctime, inode->i_ctime);
}

#ifndef SUPER_NOLOCK
static inline DBT *ftfs_get_read_lock(struct ftfs_inode *f_inode)
{
	down_read(&f_inode->key_lock);
	return &f_inode->meta_dbt;
}

static inline void ftfs_put_read_lock(struct ftfs_inode *f_inode)
{
	up_read(&f_inode->key_lock);
}

static inline DBT *ftfs_get_write_lock(struct ftfs_inode *f_inode)
{
	down_write(&f_inode->key_lock);
	return &f_inode->meta_dbt;
}

static inline void ftfs_put_write_lock(struct ftfs_inode *f_inode)
{
	up_write(&f_inode->key_lock);
}
#else
static inline DBT *ftfs_get_read_lock(struct ftfs_inode *f_inode)
{
	return &f_inode->meta_dbt;
}

static inline void ftfs_put_read_lock(struct ftfs_inode *f_inode)
{
}

static inline DBT *ftfs_get_write_lock(struct ftfs_inode *f_inode)
{
	return &f_inode->meta_dbt;
}

static inline void ftfs_put_write_lock(struct ftfs_inode *f_inode)
{
}
#endif


// get the next available (unused ino)
// we alloc some ino to each cpu, if more are needed, we will do update_ino
static int ftfs_next_ino(struct ftfs_sb_info *sbi, ino_t *ino)
{
	int ret = 0;
	unsigned int cpu;
	ino_t new_max;
	DB_TXN *txn;

	new_max = 0;
	cpu = get_cpu();
	*ino = per_cpu_ptr(sbi->s_ftfs_info, cpu)->next_ino;
	if (*ino >= per_cpu_ptr(sbi->s_ftfs_info, cpu)->max_ino) {
		// we expand for all cpus here, it is lavish
		// we can't do txn while holding cpu
		new_max = per_cpu_ptr(sbi->s_ftfs_info, cpu)->max_ino +
		          sbi->s_nr_cpus * FTFS_INO_INC;
		per_cpu_ptr(sbi->s_ftfs_info, cpu)->max_ino = new_max;
	}
	per_cpu_ptr(sbi->s_ftfs_info, cpu)->next_ino += sbi->s_nr_cpus;
	put_cpu();

	if (new_max) {
		TXN_GOTO_LABEL(retry);
		ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
		ret = ftfs_bstore_update_ino(sbi->meta_db, txn, new_max);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
			// we already updated max_cpu, if we get error here
			//  it is hard to go back
			BUG();
		}
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}

	return ret;
}

static int alloc_meta_dbt_from_ino(DBT *dbt, uint64_t ino)
{
	char *meta_key;
	size_t size;

	size = SIZEOF_CIRCLE_ROOT_META_KEY;
	meta_key = kmalloc(size, GFP_NOIO);
	if (meta_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(meta_key, META_KEY_MAGIC);
	ftfs_key_set_ino(meta_key, ino);
	(ftfs_key_path(meta_key))[0] = '\0';

	dbt_setup(dbt, meta_key, size);
	return 0;
}

void copy_meta_dbt_from_ino(DBT *dbt, uint64_t ino)
{
	char *meta_key = dbt->data;
	size_t size;

	size = SIZEOF_CIRCLE_ROOT_META_KEY;
	BUG_ON(size > dbt->ulen);
	ftfs_key_set_magic(meta_key, META_KEY_MAGIC);
	ftfs_key_set_ino(meta_key, ino);
	(ftfs_key_path(meta_key))[0] = '\0';

	dbt->size = size;
}

void
copy_data_dbt_from_meta_dbt(DBT *data_dbt, DBT *meta_dbt, uint64_t block_num)
{
	char *meta_key = meta_dbt->data;
	char *data_key = data_dbt->data;
	size_t size;

	size = meta_dbt->size + DATA_META_KEY_SIZE_DIFF;
	BUG_ON(size > data_dbt->ulen);
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_copy_ino(data_key, meta_key);
	strcpy(ftfs_key_path(data_key), ftfs_key_path(meta_key));
	ftfs_data_key_set_blocknum(data_key, size, block_num);

	data_dbt->size = size;
}

int
alloc_data_dbt_from_meta_dbt(DBT *data_dbt, DBT *meta_dbt, uint64_t block_num)
{
	char *meta_key = meta_dbt->data;
	char *data_key;
	size_t size;

	size = meta_dbt->size + DATA_META_KEY_SIZE_DIFF;
	data_key = kmalloc(size, GFP_NOIO);
	if (data_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_copy_ino(data_key, meta_key);
	strcpy(ftfs_key_path(data_key), ftfs_key_path(meta_key));
	ftfs_data_key_set_blocknum(data_key, size, block_num);

	dbt_setup(data_dbt, data_key, size);
	return 0;
}

int
alloc_child_meta_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt, const char *name)
{
	char *parent_key = parent_dbt->data;
	char *meta_key;
	size_t size;
	char *last_slash;

	if ((ftfs_key_path(parent_key))[0] == '\0')
		size = parent_dbt->size + strlen(name) + 2;
	else
		size = parent_dbt->size + strlen(name) + 1;
	meta_key = kmalloc(size, GFP_NOIO);
	if (meta_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(meta_key, META_KEY_MAGIC);
	ftfs_key_copy_ino(meta_key, parent_key);
	if ((ftfs_key_path(parent_key))[0] == '\0') {
		sprintf(ftfs_key_path(meta_key), "\x01\x01%s", name);
	} else {
		last_slash = strrchr(ftfs_key_path(parent_key), '\x01');
		BUG_ON(last_slash == NULL);
		memcpy(ftfs_key_path(meta_key), ftfs_key_path(parent_key),
		       last_slash - ftfs_key_path(parent_key));
		sprintf(ftfs_key_path(meta_key) + (last_slash - ftfs_key_path(parent_key)),
		        "%s\x01\x01%s", last_slash + 1, name);
	}

	dbt_setup(dbt, meta_key, size);
	return 0;
}

void
copy_data_dbt_from_inode(DBT *data_dbt, struct inode *inode, uint64_t block_num)
{
	char *data_key = data_dbt->data;
	size_t size;
	uint64_t ino = inode->i_ino;

	size = PATH_POS + DATA_META_KEY_SIZE_DIFF;
	BUG_ON(size > data_dbt->ulen);
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_set_ino(data_key, ino);
	ftfs_data_key_set_blocknum(data_key, size, block_num);

	data_dbt->size = size;
}

int
alloc_data_dbt_from_inode(DBT *data_dbt, struct inode *inode, uint64_t block_num)
{
	char *data_key;
	size_t size;
	uint64_t ino = inode->i_ino;

	size = PATH_POS + DATA_META_KEY_SIZE_DIFF;
	data_key = kmalloc(size, GFP_NOIO);
	if (data_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_set_ino(data_key, ino);
	ftfs_data_key_set_blocknum(data_key, size, block_num);

	dbt_setup(data_dbt, data_key, size);
	return 0;
}

int
alloc_data_dbt_from_ino(DBT *data_dbt, uint64_t ino, uint64_t block_num)
{
	char *data_key;
	size_t size;

	size = PATH_POS + DATA_META_KEY_SIZE_DIFF;
	data_key = kmalloc(size, GFP_NOIO);
	if (data_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_set_ino(data_key, ino);
	ftfs_data_key_set_blocknum(data_key, size, block_num);

	dbt_setup(data_dbt, data_key, size);
	return 0;
}


int
alloc_child_meta_dbt_from_inode(DBT *dbt, struct inode *dir, const char *name)
{
	char *meta_key;
	size_t size;
	uint64_t parent_ino = dir->i_ino;

	size = PATH_POS + strlen(name) + 1;
	meta_key = kmalloc(size, GFP_NOIO);
	if (meta_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(meta_key, META_KEY_MAGIC);
	ftfs_key_set_ino(meta_key, parent_ino);
	sprintf(ftfs_key_path(meta_key), "%s", name);

	dbt_setup(dbt, meta_key, size);
	return 0;
}

//TODO: KOO fix it.
int alloc_meta_dbt_prefix(DBT *prefix_dbt, DBT *meta_dbt)
{
	char *meta_key = meta_dbt->data;
	char *prefix_key;
	size_t size;
	char *last_slash;

	if ((ftfs_key_path(meta_key))[0] == '\0')
		size = meta_dbt->size;
	else
		size = meta_dbt->size - 1;
	prefix_key = kmalloc(size, GFP_NOIO);
	if (prefix_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(prefix_key, META_KEY_MAGIC);
	ftfs_key_copy_ino(prefix_key, meta_key);
	if ((ftfs_key_path(meta_key))[0] == '\0') {
		(ftfs_key_path(prefix_key))[0] = '\0';
	} else {
		last_slash = strrchr(ftfs_key_path(meta_key), '\x01');
		BUG_ON(last_slash == NULL);
		memcpy(ftfs_key_path(prefix_key), ftfs_key_path(meta_key),
		       last_slash - ftfs_key_path(meta_key));
		strcpy(ftfs_key_path(prefix_key) + (last_slash - ftfs_key_path(meta_key)),
		       last_slash + 1);
	}

	dbt_setup(prefix_dbt, prefix_key, size);
	return 0;
}

static int alloc_meta_dbt_movdir(DBT *old_prefix_dbt, DBT *new_prefix_dbt,
                                 DBT *old_dbt, DBT *new_dbt)
{
	char *new_prefix_key = new_prefix_dbt->data;
	char *old_key = old_dbt->data;
	char *new_key;
	size_t size;

	size = old_dbt->size - old_prefix_dbt->size + new_prefix_dbt->size;
	new_key = kmalloc(size, GFP_NOIO);
	if (new_key == NULL)
		return -ENOMEM;
	ftfs_key_set_magic(new_key, META_KEY_MAGIC);
	ftfs_key_copy_ino(new_key, new_prefix_key);
	sprintf(ftfs_key_path(new_key), "%s%s", ftfs_key_path(new_prefix_key),
	        old_key + old_prefix_dbt->size - 1);

	dbt_setup(new_dbt, new_key, size);
	return 0;
}

static struct inode *
ftfs_setup_inode(struct super_block *sb, DBT *meta_dbt,
                 struct ftfs_metadata *meta);

static int
ftfs_do_unlink(DBT *meta_dbt, DB_TXN *txn, struct inode *inode,
               struct ftfs_sb_info *sbi)
{
	int ret;


	//ftfs_error(__func__, "어디여?\n");
	ret = ftfs_bstore_meta_del(sbi->meta_db, meta_dbt, txn, 0);
	if (!ret && i_size_read(inode) > 0)
		ret = ftfs_bstore_trunc(sbi->data_db, meta_dbt, txn, 0, 0, inode);

	return ret;
}

/*
 * we are not just renaming to files (old->new), we are renaming
 * entire subtrees of files.
 *
 * we lock the whole subtree before rename for exclusive access. for
 * either success or fail, you have to call unlock or else you are
 * hosed
 *
 * only the children are locked not the parent
 */
static int prelock_children_for_rename(struct dentry *object, struct list_head *locked)
{
	struct dentry *this_parent;
	struct list_head *next;
	struct inode *inode;
	uint64_t object_ino;
	DBT *dbt;

	this_parent = object;
	dbt = &FTFS_I(object->d_inode)->meta_dbt;
	object_ino = ftfs_key_get_ino((char *)dbt->data);
start:
	if (this_parent->d_sb != object->d_sb)
		goto end;
	inode = this_parent->d_inode;
	if (inode == NULL)
		goto repeat;
	if (this_parent != object) {
		dbt = ftfs_get_write_lock(FTFS_I(inode));
		// we don't need to lock inodes in another circle
		if (ftfs_key_get_ino((char *)dbt->data) != object_ino) {
			ftfs_put_write_lock(FTFS_I(inode));
			goto end;
		}
		list_add(&FTFS_I(inode)->rename_locked, locked);
	}
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		this_parent = list_entry(next, struct dentry, d_child);
		goto start;
	}
end:
	if (this_parent != object) {
		next = this_parent->d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
	return 0;
}

static int unlock_children_after_rename(struct list_head *locked)
{
	struct ftfs_inode *f_inode, *tmp;

	list_for_each_entry_safe(f_inode, tmp, locked, rename_locked) {
		ftfs_put_write_lock(f_inode);
		list_del_init(&f_inode->rename_locked);
	}
	return 0;
}

static void
ftfs_update_ftfs_inode_keys(struct list_head *locked,
                            DBT *old_meta_dbt, DBT *new_meta_dbt)
{
	int ret;
	struct ftfs_inode *f_inode, *tmp;
	DBT tmp_dbt, old_prefix_dbt, new_prefix_dbt;

	if (list_empty(locked))
		return;

	ret = alloc_meta_dbt_prefix(&old_prefix_dbt, old_meta_dbt);
	BUG_ON(ret);
	alloc_meta_dbt_prefix(&new_prefix_dbt, new_meta_dbt);
	BUG_ON(ret);

	list_for_each_entry_safe(f_inode, tmp, locked, rename_locked) {
		dbt_copy(&tmp_dbt, &f_inode->meta_dbt);
		ret = alloc_meta_dbt_movdir(&old_prefix_dbt, &new_prefix_dbt,
		                            &tmp_dbt, &f_inode->meta_dbt);
		BUG_ON(ret);
		dbt_destroy(&tmp_dbt);
	}

	dbt_destroy(&old_prefix_dbt);
	dbt_destroy(&new_prefix_dbt);
}

static inline int meta_key_is_circle_root(char *meta_key)
{
	return 1;
	return ((ftfs_key_path(meta_key))[0] == '\0');
}


// ifndef FTFS_CIRCLE, this is called for hard link
static int split_circle(struct dentry *dentry)
{
	int ret;
	uint64_t circle_id;
	struct ftfs_sb_info *sbi = dentry->d_sb->s_fs_info;
	DBT *old_dbt, new_dbt;
	struct inode *inode = dentry->d_inode;
	struct ftfs_metadata meta, redirect_meta;
	LIST_HEAD(locked_children);
	DB_TXN *txn;

	old_dbt = ftfs_get_write_lock(FTFS_I(inode));
	if (meta_key_is_circle_root(old_dbt->data)) {
		ftfs_put_write_lock(FTFS_I(inode));
		return 0;
	}
	circle_id = inode->i_ino;
	ret = alloc_meta_dbt_from_ino(&new_dbt, circle_id);
	if (ret) {
		ftfs_put_write_lock(FTFS_I(inode));
		return ret;
	}
	prelock_children_for_rename(dentry, &locked_children);
	ftfs_copy_metadata_from_inode(&meta, inode);
	redirect_meta.type = FTFS_METADATA_TYPE_REDIRECT;
	redirect_meta.u.ino = circle_id;
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	ret = ftfs_bstore_meta_put(sbi->meta_db, old_dbt, txn, &redirect_meta);
	if (ret)
		goto abort;
	ret = ftfs_bstore_meta_put(sbi->meta_db, &new_dbt, txn, &meta);
	if (ret)
		goto abort;
	ret = ftfs_bstore_move(sbi->meta_db, sbi->data_db, old_dbt, &new_dbt,
	                       txn, ftfs_bstore_get_move_type(&meta));
	if (ret)
		goto abort;
	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	if (!ret) {
		ftfs_update_ftfs_inode_keys(&locked_children, old_dbt, &new_dbt);
		dbt_destroy(&FTFS_I(inode)->meta_dbt);
		dbt_copy(&FTFS_I(inode)->meta_dbt, &new_dbt);
	} else {
		dbt_destroy(&new_dbt);
	}

unlock_out:
	unlock_children_after_rename(&locked_children);
	ftfs_put_write_lock(FTFS_I(inode));

	return ret;
abort:
	ftfs_bstore_txn_abort(txn);
	dbt_destroy(&new_dbt);
	goto unlock_out;
}

static int ftfs_readpage(struct file *file, struct page *page)
{
	int ret;
	struct inode *inode = page->mapping->host;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	DBT *meta_dbt;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	ftfs_error(__func__, "\n");

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
	ret = ftfs_bstore_scan_one_page(sbi->data_db, meta_dbt, txn, page, inode);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}

	ftfs_put_read_lock(FTFS_I(inode));

	flush_dcache_page(page);
	if (!ret) {
		SetPageUptodate(page);
	} else {
		ClearPageUptodate(page);
		SetPageError(page);
	}

	unlock_page(page); //TMP 

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int ftfs_readpages(struct file *filp, struct address_space *mapping,
                          struct list_head *pages, unsigned nr_pages)
{
	int ret;
	struct ftfs_sb_info *sbi = mapping->host->i_sb->s_fs_info;
	struct ftfs_inode *ftfs_inode = FTFS_I(mapping->host);
	struct ftio *ftio;
	DBT *meta_dbt;
	DB_TXN *txn;
	struct inode *inode = mapping->host;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif


#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif


	ftio = ftio_alloc(nr_pages);
	if (!ftio)
		return -ENOMEM;
	ftio_setup(ftio, pages, nr_pages, mapping);
	ftfs_error(__func__, "%d\n", nr_pages);

	meta_dbt = ftfs_get_read_lock(ftfs_inode);

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);

	ret = ftfs_bstore_scan_pages(sbi->data_db, meta_dbt, txn, ftio, inode);

	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}

	ftfs_put_read_lock(ftfs_inode);

	if (ret)
		ftio_set_pages_error(ftio);
	else
		ftio_set_pages_uptodate(ftio);
	ftio_unlock_pages(ftio); 
	ftio_free(ftio);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	return ret;
}

#ifdef LIGHTFS_UPSERT
static int
__ftfs_updatepage(struct ftfs_sb_info *sbi, struct inode *inode, DBT *meta_dbt,
                  struct page *page, size_t len, loff_t offset, DB_TXN *txn)
{
	int ret;
	char *buf;
	size_t off;
	DBT data_dbt;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	// now data_db keys start from 1
	// KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt,
	//                                   PAGE_TO_BLOCK_NUM(page));
	ret = alloc_data_dbt_from_inode(&data_dbt, inode, PAGE_TO_BLOCK_NUM(page));

	if (ret)
		return ret;
	buf = kmap_atomic(page);
	buf = buf + (offset & ~PAGE_MASK);
	off = block_get_off_by_position(offset);
	//ftfs_error(__func__, "page_mask: %llu, get_off: %llu\n", offset & ~PAGE_MASK, off);
	ret = ftfs_bstore_update(sbi->data_db, &data_dbt, txn, buf, len, off);
	kunmap_atomic(buf);
	dbt_destroy(&data_dbt);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	return ret;
}
#endif

static int
__ftfs_writepage(struct ftfs_sb_info *sbi, struct inode *inode, DBT *meta_dbt,
                 struct page *page, size_t len, DB_TXN *txn)
{
	int ret;
	char *buf;
	DBT data_dbt;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	// now data_db keys start from 1
	// KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt,
	//                                   PAGE_TO_BLOCK_NUM(page));
	ret = alloc_data_dbt_from_inode(&data_dbt, inode, PAGE_TO_BLOCK_NUM(page));
	if (ret)
		return ret;
	buf = kmap_atomic(page);
	ret = ftfs_bstore_put(sbi->data_db, &data_dbt, txn, buf, len, 0);
	kunmap_atomic(buf);
	dbt_destroy(&data_dbt);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	return ret;
}

static int
ftfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret;
	DBT *meta_dbt;
	struct inode *inode = page->mapping->host;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t i_size;
	pgoff_t end_index;
	unsigned offset;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
	set_page_writeback(page);
	i_size = i_size_read(inode);
	end_index = i_size >> PAGE_SHIFT;

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	if (page->index < end_index)
		ret = __ftfs_writepage(sbi, inode, meta_dbt, page, PAGE_SIZE, txn);
	else {
		offset = i_size & (~PAGE_MASK);
		if (page->index == end_index && offset != 0)
			ret = __ftfs_writepage(sbi, inode, meta_dbt, page, offset, txn);
		else
			ret = 0;
	}
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
		if (ret == -EAGAIN) {
			redirty_page_for_writepage(wbc, page);
			ret = 0;
		} else {
			SetPageError(page);
			mapping_set_error(page->mapping, ret);
		}
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}
	end_page_writeback(page);

	ftfs_put_read_lock(FTFS_I(inode));
	unlock_page(page); 

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

/*
static inline void *radix_indirect_to_ptr(void *ptr)
{
	return (void *)((unsigned long)ptr & ~RADIX_TREE_INDIRECT_PTR);
}
*/

/**
 * (copied from lib/radix-tree.c:radix_tree_gang_lookup_tagged())
 *	radix_tree_tag_count_exceeds - perform multiple lookup on a radix tree
 *	                             based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the items at *@results and
 *	returns the number of items which were placed at *@results.
 */
static unsigned int
radix_tree_tag_count_exceeds(struct radix_tree_root *root,
			unsigned long first_index, unsigned int threshold,
			unsigned int tag)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	unsigned int count = 0;
	void *rcu_ret = NULL;

	if (unlikely(!threshold))
		return 0;

	radix_tree_for_each_tagged(slot, root, &iter, first_index, tag) {
		rcu_ret = rcu_dereference_raw(*slot);
		if (!rcu_ret)
			continue;
		if (radix_tree_is_internal_node(rcu_ret)) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}
		if (++count == threshold)
			return 1;
		/*
		if (!radix_indirect_to_ptr(rcu_dereference_raw(*slot)))
			continue;
		if (++count == threshold)
			return 1;
		*/
	}

	return 0;
}

struct ftfs_wp_node {
	struct page *page;
	struct ftfs_wp_node *next;
};
#define FTFS_WRITEPAGES_LIST_SIZE 4096

static struct kmem_cache *ftfs_writepages_cachep;

static int
__ftfs_writepages_write_pages(struct ftfs_wp_node *list, int nr_pages,
                              struct writeback_control *wbc,
                              struct inode *inode, struct ftfs_sb_info *sbi,
                              DBT *data_dbt, int is_seq)
{
	int i, ret;
	loff_t i_size;
	pgoff_t end_index;
	unsigned offset;
	char *buf;
	struct ftfs_wp_node *it;
	struct page *page;
	DBT *meta_dbt;
	char *data_key;
	DB_TXN *txn = NULL;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
	data_key = data_dbt->data;
	if (unlikely(!key_is_same_of_key((char *)meta_dbt->data, data_key))) // KOO:key: is it necessary?
		copy_data_dbt_from_meta_dbt(data_dbt, meta_dbt, 0);
retry:
	i_size = i_size_read(inode);
	end_index = i_size >> PAGE_SHIFT;
	offset = i_size & (PAGE_SIZE - 1);

	//ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	// we did a lazy approach about the list, so we need an additional i here
	for (i = 0, it = list->next; i < nr_pages; i++, it = it->next) {
		if (!(i % LIGHTFS_TXN_LIMIT)) {
			ftfs_bstore_txn_begin(sbi->db_dev, NULL, &txn, TXN_MAY_WRITE);
		}
		page = it->page;
		ftfs_data_key_set_blocknum(data_key, data_dbt->size,
		                           PAGE_TO_BLOCK_NUM(page));
		buf = kmap_atomic(page);
		if (page->index < end_index)
			ret = ftfs_bstore_put(sbi->data_db, data_dbt, txn, buf,
			                      PAGE_SIZE, is_seq);
		else if (page->index == end_index && offset != 0)
			ret = ftfs_bstore_put(sbi->data_db, data_dbt, txn, buf,
			                      offset, is_seq);
		else
			ret = 0;
		kunmap_atomic(buf);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
			goto out;
		}
		if ((i % LIGHTFS_TXN_LIMIT) == LIGHTFS_TXN_LIMIT-1) {
			//ftfs_error(__func__, "존나 크네...%d\n", i);
			ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
			COMMIT_JUMP_ON_CONFLICT(ret, retry);
			txn = NULL;
		}

	}
	if (txn) {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}
out:
	ftfs_put_read_lock(FTFS_I(inode));
	for (i = 0, it = list->next; i < nr_pages; i++, it = it->next) {
		page = it->page;
		end_page_writeback(page);
		if (ret)
			redirty_page_for_writepage(wbc, page);
		unlock_page(page); //TMP
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

/**
 * (mostly) copied from write_cache_pages
 *
 * however, instead of calling mm/page-writeback.c:__writepage, we
 * detect large I/Os and potentially issue a special seq_put to our
 * B^e tree
 */
static int ftfs_writepages(struct address_space *mapping,
			struct writeback_control *wbc)
{
	int ret = 0;
	int done = 0;
	struct pagevec pvec;
	int nr_pages;
	pgoff_t uninitialized_var(writeback_index);
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index, txn_done_index;
	int cycled;
	int range_whole = 0;
	int tag;
	//int is_seq = 0;
	struct inode *inode;
	struct ftfs_sb_info *sbi;
	DBT *meta_dbt, data_dbt;
	int nr_list_pages;
	struct ftfs_wp_node list, *tail, *it;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	pagevec_init(&pvec);
	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index; /* prev offset */
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */
	}
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;
retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);
	done_index = index;
	txn_done_index = index;

	/* wkj: add count of total pages for writeback: we need to
	 * detect sequential I/Os somehow. */
	//if (range_whole || (end - index >= LARGE_IO_THRESHOLD))
	//	is_seq = radix_tree_tag_count_exceeds(&mapping->page_tree,
	//	                           	index, LARGE_IO_THRESHOLD, tag);

	inode = mapping->host;
	sbi = inode->i_sb->s_fs_info;
	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
	ret = dbt_alloc(&data_dbt, DATA_KEY_MAX_LEN);
	if (ret) {
		ftfs_put_read_lock(FTFS_I(inode));
		goto out;
	}
	//copy_data_dbt_from_meta_dbt(&data_dbt, meta_dbt, 0); //TODO:key
	copy_data_dbt_from_inode(&data_dbt, inode, 0);
	ftfs_put_read_lock(FTFS_I(inode));

	nr_list_pages = 0;
	list.next = NULL;
	tail = &list;
	while (!done && (index <= end)) {
		int i;
		//nr_pages = pagevec_lookup_tag(&pvec, mapping, &index, tag); //asd
		nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end, tag);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			if (page->index > end) {
				done = 1;
				break;
			}

			txn_done_index = page->index;
			lock_page(page); 

			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page); 
				continue;
			}

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (PageWriteback(page)) {
				if (wbc->sync_mode != WB_SYNC_NONE)
					wait_on_page_writeback(page);
				else
					goto continue_unlock;
			}

			BUG_ON(PageWriteback(page));
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			set_page_writeback(page); //asd
			if (tail->next == NULL) {
				tail->next = kmem_cache_alloc(
					ftfs_writepages_cachep, GFP_NOIO);
				tail->next->next = NULL;
			}
			tail = tail->next;
			tail->page = page;
			++nr_list_pages;
			if (nr_list_pages >= FTFS_WRITEPAGES_LIST_SIZE) {
				ret = __ftfs_writepages_write_pages(&list,
					nr_list_pages, wbc, inode, sbi,
					&data_dbt, 0);
				if (ret)
					goto free_dkey_out;
				done_index = txn_done_index;
				nr_list_pages = 0;
				tail = &list;
			}

			if (--wbc->nr_to_write <= 0 &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	if (nr_list_pages > 0) {
		ret = __ftfs_writepages_write_pages(&list, nr_list_pages, wbc,
			inode, sbi, &data_dbt, 0);
		if (!ret)
			done_index = txn_done_index;
	}
free_dkey_out:
	dbt_destroy(&data_dbt);
	tail = list.next;
	while (tail != NULL) {
		it = tail->next;
		kmem_cache_free(ftfs_writepages_cachep, tail);
		tail = it;
	}
out:
	if (!cycled && !done) {
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int
ftfs_write_begin(struct file *file, struct address_space *mapping,
                 loff_t pos, unsigned len, unsigned flags,
                 struct page **pagep, void **fsdata)
{
	int ret = 0;
	struct page *page;
	struct inode *inode = mapping->host;
	//struct dentry *dentry = file_dentry(file);
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned from, to;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	DBT *meta_dbt;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

	from = pos & (PAGE_SIZE -1);
	to = from + len;
#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	page = grab_cache_page_write_begin(mapping, index, flags);
	//page = pagecache_get_page(mapping, index, FGP_LOCK | FGP_WRITE | FGP_CREAT, GFP_NOIO);
	if (!page) {
		pr_info("메모리가 부족햐~~!!\n");
		ret = -ENOMEM;
	}

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	/*
#ifndef LIGHTFS_UPSERT
	if (!PageDirty(page) && pos + len <= i_size_read(inode)) {
		if (to != PAGE_SIZE || from) {
			meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
			TXN_GOTO_LABEL(retry);
		
			//ftfs_error(__func__, "pos: %llu, len: %llu, from: %llu, to: %llu, file_size: %llu, file_name: %s\n", pos, len, from, to, i_size_read(inode), dentry->d_name.name);
		
			ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
			ret = ftfs_bstore_scan_one_page(sbi->data_db, meta_dbt, txn, page, inode);
			if (ret) {
				DBOP_JUMP_ON_CONFLICT(ret, retry);
				ftfs_bstore_txn_abort(txn);
			} else {
				ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
				COMMIT_JUMP_ON_CONFLICT(ret, retry);
			}
			ftfs_put_read_lock(FTFS_I(inode));
			BUG_ON(ret);
		}
	}
#endif
*/
	/* don't read page if not uptodate */

	*pagep = page;

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int
ftfs_write_end(struct file *file, struct address_space *mapping,
               loff_t pos, unsigned len, unsigned copied,
               struct page *page, void *fsdata)
{
	/* make sure that ftfs can't guarantee uptodate page */
	loff_t last_pos = pos + copied;
	struct inode *inode = page->mapping->host;
	loff_t old_size = inode->i_size;
	char *buf;
	bool i_size_changed = 0;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#if 0
	if (PageDirty(page) || copied == PAGE_SIZE) {
	//ftfs_error(__func__, "111 copied: %llu, pos: %llu, file size: %llu, index: %llu file_name: %s\n", copied, pos, i_size_read(inode), page->index, file_dentry(file)->d_name.name);
		goto postpone_to_writepage;
	} else if (page_offset(page) >= i_size_read(inode)) {
		buf = kmap(page);
		if (pos & ~PAGE_MASK)
			memset(buf, 0, pos & ~PAGE_MASK);
		if (last_pos & ~PAGE_MASK)
			memset(buf + (last_pos & ~PAGE_MASK), 0,
			       PAGE_SIZE - (last_pos & ~PAGE_MASK));
		kunmap(page);
	//ftfs_error(__func__, "222 copied: %llu, pos: %llu, file size: %llu, index: %llu file_name: %s\n", copied, pos, i_size_read(inode), page->index, file_dentry(file)->d_name.name);
postpone_to_writepage:
		SetPageUptodate(page);
		if (!PageDirty(page))
			__set_page_dirty_nobuffers(page);
	} else {
#ifdef LIGHTFS_UPSERT
		meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
		TXN_GOTO_LABEL(retry);
		
	//ftfs_error(__func__, "333 copied: %llu, pos: %llu, file size: %llu, index: %llu file_name: %s\n", copied, pos, i_size_read(inode), page->index, file_dentry(file)->d_name.name);
		
		ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
		ret = __ftfs_updatepage(sbi, inode, meta_dbt, page, copied, pos,
		                        txn);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
		} else {
			ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
			COMMIT_JUMP_ON_CONFLICT(ret, retry);
		}

		ftfs_put_read_lock(FTFS_I(inode));
		BUG_ON(ret);
		clear_page_dirty_for_io(page);
#else
		SetPageUptodate(page);
		if (!PageDirty(page))
			__set_page_dirty_nobuffers(page);
#endif
	}

	unlock_page(page);
	put_page(page);
	//page_cache_release(page);

	/* holding i_mutconfigex */
	if (last_pos > i_size_read(inode)) {
		i_size_write(inode, last_pos);
		mark_inode_dirty(inode);
	}

	return copied;
#endif


#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	if (!PageUptodate(page)) {
		if (copied < len) {
			ftfs_error(__func__, "copy!!!\n");
		}
		SetPageUptodate(page);
	}
	//SetPageUptodate(page); // asd
	if (!PageDirty(page))
		__set_page_dirty_nobuffers(page); //asd
		//set_page_dirty(page);
	//if (!PageDirty(page)) //asd
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif


	if (last_pos > inode->i_size) {
		i_size_write(inode, last_pos);
		i_size_changed = 1;
	}

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif
	unlock_page(page);
	put_page(page);
	//page_cache_release(page);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif
	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);

	if (i_size_changed) {
		mark_inode_dirty(inode);
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return copied;
}

/* Called before freeing a page - it writes back the dirty page.
 *
 * To prevent redirtying the page, it is kept locked during the whole
 * operation.
 */
static int ftfs_launder_page(struct page *page)
{
	printk(KERN_CRIT "laundering page.\n");
	BUG();
}

static int ftfs_rename(struct inode *old_dir, struct dentry *old_dentry,
                       struct inode *new_dir, struct dentry *new_dentry,
					   unsigned int flags)
{
	int ret, err;
	struct inode *old_inode, *new_inode;
	struct ftfs_sb_info *sbi = old_dir->i_sb->s_fs_info;
	DBT *old_meta_dbt, new_meta_dbt, *old_dir_meta_dbt, *new_dir_meta_dbt,
	    *new_inode_meta_dbt;
	struct ftfs_metadata old_meta;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif


	// to prevent any other move from happening, we grab sem of parents
	old_dir_meta_dbt = ftfs_get_read_lock(FTFS_I(old_dir));
	new_dir_meta_dbt = ftfs_get_read_lock(FTFS_I(new_dir));

	old_inode = old_dentry->d_inode;
	old_meta_dbt = ftfs_get_write_lock(FTFS_I(old_inode));
	new_inode = new_dentry->d_inode;
	new_inode_meta_dbt = new_inode ?
		ftfs_get_write_lock(FTFS_I(new_inode)) : NULL;
	//prelock_children_for_rename(old_dentry, &locked_children);

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);

	if (flags & RENAME_WHITEOUT) {
		ret = -ENOENT;
		goto abort;
	}

	if (new_inode) { // 새로운 파일이 이미 존재
		if (S_ISDIR(old_inode->i_mode)) { // 기존이 디렉토리
			if (!S_ISDIR(new_inode->i_mode)) { // 새로운게 일반 파일
				ret = -ENOTDIR;
				goto abort;
			}
			err = ftfs_dir_is_empty(sbi->meta_db, new_inode_meta_dbt,
			                        txn, &ret, new_inode);
			if (err) {
				DBOP_JUMP_ON_CONFLICT(err, retry);
				ret = err;
				goto abort;
			}
			if (!ret) {
				ret = -ENOTEMPTY;
				goto abort;
			}
		} else { // old 가 그냥 파일
			if (S_ISDIR(new_inode->i_mode)) {
				ret = -ENOTDIR;
				goto abort;
			}
		}
	}

	//KOO:key
	//ret = alloc_child_meta_dbt_from_meta_dbt(&new_meta_dbt,
	//		new_dir_meta_dbt, new_dentry->d_name.name);
	ret = alloc_child_meta_dbt_from_inode(&new_meta_dbt, new_dir, new_dentry->d_name.name);
	if (ret)
		goto abort;

	ftfs_copy_metadata_from_inode(&old_meta, old_inode);
	ret = ftfs_bstore_meta_del(sbi->meta_db, old_meta_dbt, txn, 0);
	if (!ret)
		ret = ftfs_bstore_meta_put(sbi->meta_db, &new_meta_dbt, txn, &old_meta);

	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		goto abort1;
	}

	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(ret, retry);

	dbt_destroy(old_meta_dbt);
	dbt_copy(old_meta_dbt, &new_meta_dbt);
	//dbt_destroy(&new_meta_dbt);

	//unlock_children_after_rename(&locked_children);
	if (new_inode) {
		drop_nlink(new_inode);
		mark_inode_dirty(new_inode);
		// avoid future updates from write_inode and evict_inode
		//if (!meta_key_is_circle_root(new_inode_meta_dbt->data))
		FTFS_I(new_inode)->ftfs_flags |= FTFS_FLAG_DELETED;
		ftfs_put_write_lock(FTFS_I(new_inode));
	}
	ftfs_put_write_lock(FTFS_I(old_inode));
	ftfs_put_read_lock(FTFS_I(old_dir));
	ftfs_put_read_lock(FTFS_I(new_dir));


#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return 0;

abort1:
	dbt_destroy(&new_meta_dbt);
abort:
	ftfs_bstore_txn_abort(txn);
	//unlock_children_after_rename(&locked_children);
	ftfs_put_write_lock(FTFS_I(old_inode));
	if (new_inode)
		ftfs_put_write_lock(FTFS_I(new_inode));
	ftfs_put_read_lock(FTFS_I(old_dir));
	ftfs_put_read_lock(FTFS_I(new_dir));

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

/*
 * ftfs_readdir: ctx->pos (vfs get from f_pos)
 *   ctx->pos == 0, readdir just starts
 *   ctx->pos == 1/2, readdir has emit dots, used by dir_emit_dots
 *   ctx->pos == 3, readdir has emit all entries
 *   ctx->pos == ?, ctx->pos stores a pointer to the position of last readdir
 */

static int ftfs_readdir(struct file *file, struct dir_context *ctx)
{
	int ret;
	struct inode *inode = file_inode(file);
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	DBT *meta_dbt;
	DB_TXN *txn;
	struct readdir_ctx *dir_ctx;
	DBC *cursor;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	//ftfs_error(__func__, "pos %d\n", ctx->pos);

	if (ctx->pos == 0) {
		if(!dir_emit_dots(file, ctx))
			return -ENOMEM;
		ctx->pos = 2;
	}

	if (ctx->pos == 2) {
		dir_ctx = kmalloc(sizeof(struct readdir_ctx), GFP_NOIO); 
		ftfs_bstore_txn_begin(dbi->db_env, NULL, &txn, TXN_READONLY);
		ret = sbi->meta_db->cursor(sbi->meta_db, txn, &cursor, LIGHTFS_META_CURSOR);
		if (ret) {
			//ftfs_error(__func__, "FUCK!!!\n");
			ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
			kfree(dir_ctx);
			return 0;
		}

		dir_ctx->cursor = cursor;
		dir_ctx->txn = txn;
		//ftfs_error(__func__, "alloc!!!! dir_ctx: %px, dir_ctx->pos: %d, dir->cursor: %px, dir->txn: %px\n", dir_ctx, dir_ctx->pos, dir_ctx->cursor, dir_ctx->txn);
	} else {
		dir_ctx = (struct readdir_ctx *)(ctx->pos);
		if (dir_ctx->pos == 3) {
			//ftfs_error(__func__, "free!!!! dir_ctx: %px, dir_ctx->pos: %d, dir->cursor: %px, dir->txn: %px\n", dir_ctx, dir_ctx->pos, dir_ctx->cursor, dir_ctx->txn);
			dir_ctx->cursor->c_close(dir_ctx->cursor);
			ftfs_bstore_txn_commit(dir_ctx->txn, DB_TXN_NOSYNC);
			kfree(dir_ctx);
			ctx->pos = 3;
			return 0;
		}
	}

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));


	//TXN_GOTO_LABEL(retry);
	//ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
	ret = ftfs_bstore_meta_readdir(sbi->meta_db, meta_dbt, txn, ctx, inode, dir_ctx);
	/*
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}
	*/

	ftfs_put_read_lock(FTFS_I(inode));

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int
ftfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret;
	struct ftfs_sb_info *sbi = file_inode(file)->i_sb->s_fs_info;
	//struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	DBT *meta_dbt;
	struct ftfs_metadata meta;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	//ftfs_error(__func__, "오메나 클났다잉\n");

	ret = generic_file_fsync(file, start, end, datasync);

	if (!ret) {

		meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
		ftfs_copy_metadata_from_inode(&meta, inode);
		TXN_GOTO_LABEL(retry);
		ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
		ret = ftfs_bstore_meta_sync_put(sbi->meta_db, meta_dbt, txn, &meta);
		//ret = ftfs_bstore_meta_put(sbi->meta_db, meta_dbt, txn, &meta);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
		} else {
			ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
			COMMIT_JUMP_ON_CONFLICT(ret, retry);
		}
		ftfs_put_read_lock(FTFS_I(inode));
	}

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int
ftfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	int ret;
	struct inode *inode = NULL;
	struct ftfs_metadata meta;
	struct ftfs_sb_info *sbi = dir->i_sb->s_fs_info;
	DBT *dir_meta_dbt, meta_dbt;
	ino_t ino;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	//if (rdev && !new_valid_dev(rdev))
	//	return -EINVAL;

	//////////////dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	//KOO:key
	//ret = alloc_child_meta_dbt_from_meta_dbt(&meta_dbt, dir_meta_dbt,
	//                                        dentry->d_name.name);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	ret = alloc_child_meta_dbt_from_inode(&meta_dbt, dir, dentry->d_name.name);
	if (ret)
		goto out;
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	ret = ftfs_next_ino(sbi, &ino);
	if (ret) {
err_free_dbt:
		dbt_destroy(&meta_dbt);
		goto out;
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif


	ftfs_setup_metadata(&meta, mode, 0, rdev, ino);
	inode = ftfs_setup_inode(dir->i_sb, &meta_dbt, &meta);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto err_free_dbt;
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	ret = ftfs_bstore_meta_put(sbi->meta_db, &meta_dbt, txn, &meta);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
		set_nlink(inode, 0);
		FTFS_I(inode)->ftfs_flags |= FTFS_FLAG_DELETED;
		dbt_destroy(&FTFS_I(inode)->meta_dbt);
		iput(inode);
		goto out;
	}
	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(ret, retry);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	d_instantiate(dentry, inode);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	cond_resched();

out:
	/////////////////////////ftfs_put_read_lock(FTFS_I(dir));
	ftfs_put_read_lock(FTFS_I(dir));
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif


	return ret;
}

static int
ftfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	return ftfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int ftfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	return ftfs_mknod(dir, dentry, mode | S_IFDIR, 0);
}

static int ftfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int r, ret;
	struct inode *inode = dentry->d_inode;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	DBT *meta_dbt;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	meta_dbt = ftfs_get_read_lock(ftfs_inode);

	if (meta_dbt->data == &root_meta_key) {
		ret = -EINVAL;
		goto out;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
	ret = ftfs_dir_is_empty(sbi->meta_db, meta_dbt, txn, &r, inode);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
		goto out;
	}

	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(ret, retry);


	if (!r)
		ret = -ENOTEMPTY;
	else {
		clear_nlink(inode);
		mark_inode_dirty(inode);
		ret = 0;
	}

out:
	ftfs_put_read_lock(ftfs_inode);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int
ftfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	int ret;
	struct inode *inode;
	struct ftfs_sb_info *sbi = dir->i_sb->s_fs_info;
	struct ftfs_metadata meta;
	DBT *dir_meta_dbt, meta_dbt;
	DBT data_dbt;
	size_t len = strlen(symname);
	ino_t ino;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif

	if (len > FTFS_BSTORE_BLOCKSIZE)
		return -ENAMETOOLONG;

	dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	// KOO:key
	//ret = alloc_child_meta_dbt_from_meta_dbt(&meta_dbt,
	//		dir_meta_dbt, dentry->d_name.name);
	ret = alloc_child_meta_dbt_from_inode(&meta_dbt, dir, dentry->d_name.name);
	if (ret)
		goto out;

	ret = ftfs_next_ino(sbi, &ino);
	if (ret) {
free_meta_out:
		dbt_destroy(&meta_dbt);
		goto out;
	}

	// now we start from 1
	// KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&data_dbt, &meta_dbt, 1);
	ret = alloc_data_dbt_from_ino(&data_dbt, ino, 1);
	if (ret) {
		goto free_meta_out;
	}

	ftfs_setup_metadata(&meta, S_IFLNK | S_IRWXUGO, len, 0, ino);
	inode = ftfs_setup_inode(dir->i_sb, &meta_dbt, &meta);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		dbt_destroy(&data_dbt);
		goto free_meta_out;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	ret = ftfs_bstore_meta_put(sbi->meta_db, &meta_dbt, txn, &meta);
	if (ret) {
abort:
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
		set_nlink(inode, 0);
		FTFS_I(inode)->ftfs_flags |= FTFS_FLAG_DELETED;
		dbt_destroy(&FTFS_I(inode)->meta_dbt);
		iput(inode);
		dbt_destroy(&data_dbt);
		goto out;
	}
	ret = ftfs_bstore_put(sbi->data_db, &data_dbt, txn, symname, len, 0);
	if (ret)
		goto abort;

	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(ret, retry);

	d_instantiate(dentry, inode);
	dbt_destroy(&data_dbt);
out:
	ftfs_put_read_lock(FTFS_I(dir));

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static int ftfs_link(struct dentry *old_dentry,
                     struct inode *dir, struct dentry *dentry)
{
	int ret;
	struct ftfs_sb_info *sbi = dentry->d_sb->s_fs_info;
	struct inode *inode = old_dentry->d_inode;
	DBT *meta_dbt, *dir_meta_dbt, new_meta_dbt;
	struct ftfs_metadata meta;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	//ftfs_error(__func__, "하드하드\n");

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));
	if (!meta_key_is_circle_root(meta_dbt->data)) {
		ftfs_put_read_lock(FTFS_I(inode));
		ret = split_circle(old_dentry);
		if (ret)
			goto out;
	} else
		ftfs_put_read_lock(FTFS_I(inode));

	dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));

	BUG_ON(!meta_key_is_circle_root(meta_dbt->data));

	//KOO:key
	//ret = alloc_child_meta_dbt_from_meta_dbt(&new_meta_dbt,
	//		dir_meta_dbt, dentry->d_name.name);
	ret = alloc_child_meta_dbt_from_inode(&new_meta_dbt, dir, dentry->d_name.name);
	if (ret)
		goto out;
	meta.type = FTFS_METADATA_TYPE_REDIRECT;
	meta.u.ino = inode->i_ino;
	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	ret = ftfs_bstore_meta_put(sbi->meta_db, &new_meta_dbt, txn, &meta);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}

	if (!ret) {
		inode->i_ctime = current_kernel_time();
		inc_nlink(inode);
		mark_inode_dirty(inode);
		ihold(inode);
		d_instantiate(dentry, inode);
	}

	dbt_destroy(&new_meta_dbt);
	ftfs_put_read_lock(FTFS_I(inode));
	ftfs_put_read_lock(FTFS_I(dir));


#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
out:
	return ret;
}

static int ftfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int ret = 0;
	struct inode *inode = dentry->d_inode;
	DBT *dir_meta_dbt, *meta_dbt;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));

	//if (meta_key_is_circle_root(meta_dbt->data)) {
	if (!meta_key_is_circle_root(meta_dbt->data)) {
	//TODO: handling hard_link
		struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
		DBT indirect_dbt;
		DB_TXN *txn;

		//KOO:key
		//ret = alloc_child_meta_dbt_from_meta_dbt(&indirect_dbt,
		//		dir_meta_dbt, dentry->d_name.name);
		ret = alloc_child_meta_dbt_from_inode(&indirect_dbt, dir, dentry->d_name.name);
		if (ret)
			goto out;
		TXN_GOTO_LABEL(retry);
		ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
		ret = ftfs_bstore_meta_del(sbi->meta_db, &indirect_dbt, txn, 0);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
		} else {
			ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
			COMMIT_JUMP_ON_CONFLICT(ret, retry);
		}
		dbt_destroy(&indirect_dbt);
out:
		ftfs_put_read_lock(FTFS_I(inode));
		ftfs_put_read_lock(FTFS_I(dir));
	} else {
		ftfs_put_read_lock(FTFS_I(inode));
		ftfs_put_read_lock(FTFS_I(dir));
	}


	if (ret)
		return ret;
	drop_nlink(inode);
	mark_inode_dirty(inode);


#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ret;
}

static struct dentry *
ftfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	int r, err;
	struct dentry *ret;
	struct inode *inode;
	struct ftfs_sb_info *sbi = dir->i_sb->s_fs_info;
	DBT *dir_meta_dbt, meta_dbt;
	DB_TXN *txn;
	struct ftfs_metadata meta;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	dir_meta_dbt = ftfs_get_read_lock(FTFS_I(dir));
	//KOO:key
	//r = alloc_child_meta_dbt_from_meta_dbt(&meta_dbt,
	//		dir_meta_dbt, dentry->d_name.name);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	r = alloc_child_meta_dbt_from_inode(&meta_dbt, dir, dentry->d_name.name);
	if (r) {
		inode = ERR_PTR(r);
		goto out;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	r = ftfs_bstore_meta_get(sbi->meta_db, &meta_dbt, txn, &meta);
	//ftfs_error(__func__, "lookup - 1\n");
	if (r == -ENOENT) {
		inode = NULL;
		dbt_destroy(&meta_dbt);
		goto commit;
	} else if (r) {
abort:
		inode = ERR_PTR(r);
		ftfs_bstore_txn_abort(txn);
		dbt_destroy(&meta_dbt);
		goto out;
	} else if (meta.type == FTFS_METADATA_TYPE_REDIRECT) {
		copy_meta_dbt_from_ino(&meta_dbt, meta.u.ino);
		r = ftfs_bstore_meta_get(sbi->meta_db, &meta_dbt, txn, &meta);
		ftfs_error(__func__, "lookup - 2\n");
		BUG_ON(r == -ENOENT);
		if (r)
			goto abort;
	}

	BUG_ON(meta.type != FTFS_METADATA_TYPE_NORMAL);
commit:
	err = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(err, retry);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	// r == -ENOENT, inode == 0
	// r == 0, get meta, need to setup inode
	// r == err, error, will not execute this code
	if (r == 0) {
		inode = ftfs_setup_inode(dir->i_sb, &meta_dbt, &meta);
		if (IS_ERR(inode))
			dbt_destroy(&meta_dbt);
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

out:
	ftfs_put_read_lock(FTFS_I(dir));
	ret = d_splice_alias(inode, dentry);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	return ret;
}

static int ftfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	int ret;
	struct inode *inode = dentry->d_inode;
	loff_t size;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	//ftfs_error(__func__, "어디여?\n");
	//ret = inode_change_ok(inode, iattr);
	ret = setattr_prepare(dentry, iattr);

	if (ret)
		return ret;

	if (is_quota_modification(inode, iattr)) {
		ret = dquot_initialize(inode);
		if (ret)
			return ret;
	}

	size = i_size_read(inode);
	if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size < size) {
		uint64_t block_num;
		size_t block_off;
		loff_t size;
		struct ftfs_inode *ftfs_inode = FTFS_I(inode);
		struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
		DBT *meta_dbt;
		DB_TXN *txn;

		size = i_size_read(inode);
		if (iattr->ia_size >= size) {
			ftfs_error(__func__, "트렁크 트렁크\n");
			goto skip_txn;
		}
		block_num = block_get_num_by_position(iattr->ia_size);
		block_off = block_get_off_by_position(iattr->ia_size);

		//ftfs_error(__func__, "장난 똥떄리냐 block_num:%d, block_off:%d, size:%d \n", block_num, block_off, size);

		meta_dbt = ftfs_get_read_lock(ftfs_inode);
		TXN_GOTO_LABEL(retry);
		ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
		ret = ftfs_bstore_trunc(sbi->data_db, meta_dbt, txn,
		                        block_num, block_off, inode);
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
			ftfs_put_read_lock(ftfs_inode);
			goto err;
		}
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
		ftfs_put_read_lock(ftfs_inode);

skip_txn:
		i_size_write(inode, iattr->ia_size);
	}

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
err:
	return ret;
}

static int ftfs_getattr(const struct path *path, struct kstat *stat,
		        u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	unsigned int flags;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif


#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	flags = inode->i_flags & (FS_FL_USER_VISIBLE | FS_PROJINHERIT_FL);
	if (flags & FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & FS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	stat->attributes_mask |= (STATX_ATTR_APPEND |
			      STATX_ATTR_COMPRESSED |
			      STATX_ATTR_ENCRYPTED |
			      STATX_ATTR_IMMUTABLE |
			      STATX_ATTR_NODUMP);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	generic_fillattr(inode, stat);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	return 0;
}

static void ftfs_put_link(void *arg) {

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	kfree(arg);
}

static const char *ftfs_get_link(struct dentry *dentry, 
		         struct inode *inode, 
				 struct delayed_call *done)
{
	int r;
	char *ret;
	void *buf;
	struct ftfs_sb_info *sbi;
	struct ftfs_inode *ftfs_inode;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	if (!dentry) {
		return ERR_PTR(-ECHILD);
	}

	sbi = dentry->d_sb->s_fs_info;
	ftfs_inode = FTFS_I(dentry->d_inode);
	DBT *meta_dbt;
	DBT data_dbt;
	DB_TXN *txn;

	buf = kmalloc(FTFS_BSTORE_BLOCKSIZE, GFP_NOIO);
	if (!buf) {
		ret = ERR_PTR(-ENOMEM);
		goto err1;
	}
	meta_dbt = ftfs_get_read_lock(ftfs_inode);
	// now block start from 1
	//KOO:key
	//r = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt, 1);
	r = alloc_data_dbt_from_inode(&data_dbt, dentry->d_inode, 1);
	if (r) {
		ret = ERR_PTR(r);
		goto err2;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
	r = ftfs_bstore_get(sbi->data_db, &data_dbt, txn, buf, dentry->d_inode);
	if (r) {
		DBOP_JUMP_ON_CONFLICT(r, retry);
		ftfs_bstore_txn_abort(txn);
		ret = ERR_PTR(r);
		goto err3;
	}
	r = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(r, retry);

	set_delayed_call(done, ftfs_put_link, buf);
	ret = buf;

err3:
	dbt_destroy(&data_dbt);
err2:
	ftfs_put_read_lock(ftfs_inode);
	if (ret != buf) {
		do_delayed_call(done);
		clear_delayed_call(done);
	}

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
err1:
	return ret;
}

/*
static void *ftfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int r;
	void *ret;
	void *buf;
	struct ftfs_sb_info *sbi = dentry->d_sb->s_fs_info;
	struct ftfs_inode *ftfs_inode = FTFS_I(dentry->d_inode);
	DBT *meta_dbt, data_dbt;
	DB_TXN *txn;

	buf = kmalloc(FTFS_BSTORE_BLOCKSIZE, GFP_NOIO);
	if (!buf) {
		ret = ERR_PTR(-ENOMEM);
		goto err1;
	}
	meta_dbt = ftfs_get_read_lock(ftfs_inode);
	// now block start from 1
	r = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt, 1);
	if (r) {
		ret = ERR_PTR(r);
		goto err2;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_READONLY);
	r = ftfs_bstore_get(sbi->data_db, &data_dbt, txn, buf);
	if (r) {
		DBOP_JUMP_ON_CONFLICT(r, retry);
		ftfs_bstore_txn_abort(txn);
		ret = ERR_PTR(r);
		goto err3;
	}
	r = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
	COMMIT_JUMP_ON_CONFLICT(r, retry);

	nd_set_link(nd, buf);

	ret = buf;
err3:
	dbt_destroy(&data_dbt);
err2:
	ftfs_put_read_lock(ftfs_inode);
	if (ret != buf)
		kfree(buf);
err1:
	return ret;
}

static void ftfs_put_link(struct dentry *dentry, struct nameidata *nd,
                          void *cookie)
{
	if (IS_ERR(cookie))
		return;
	kfree(cookie);
}

*/

static struct inode *ftfs_alloc_inode(struct super_block *sb)
{
	struct ftfs_inode *ftfs_inode;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	ftfs_inode = kmem_cache_alloc(ftfs_inode_cachep, GFP_NOIO);
	// initialization in ftfs_i_init_once

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return ftfs_inode ? &ftfs_inode->vfs_inode : NULL;
}

static void lightfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ftfs_inode_cachep, FTFS_I(inode));
}

static void ftfs_destroy_inode(struct inode *inode)
{
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	ftfs_get_write_lock(ftfs_inode);
	if (ftfs_inode->meta_dbt.data &&
	    ftfs_inode->meta_dbt.data != &root_meta_key)
		dbt_destroy(&ftfs_inode->meta_dbt);
	ftfs_put_write_lock(ftfs_inode);

	call_rcu(&inode->i_rcu, lightfs_i_callback);
	//kmem_cache_free(ftfs_inode_cachep, ftfs_inode);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
}

static int
ftfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret = 0;
	DB_TXN *txn;
	DBT *meta_dbt;
	struct ftfs_metadata meta;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	if (inode->i_nlink == 0)
		goto no_write;

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));


	ftfs_copy_metadata_from_inode(&meta, inode);

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	ret = ftfs_bstore_meta_put(sbi->meta_db, meta_dbt, txn, &meta);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
	}

	ftfs_put_read_lock(FTFS_I(inode));

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
no_write:
	return ret;
}

static void ftfs_evict_inode(struct inode *inode)
{
	int ret;
	struct ftfs_sb_info *sbi = inode->i_sb->s_fs_info;
	DBT *meta_dbt;
	DB_TXN *txn;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif


#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	if (inode->i_nlink || (FTFS_I(inode)->ftfs_flags & FTFS_FLAG_DELETED)) {
		ftfs_error(__func__, "쫒겨난다\n");
		ftfs_bstore_meta_del(sbi->cache_db, &(FTFS_I(inode)->meta_dbt), NULL, 1);
		goto no_delete;
	}

	meta_dbt = ftfs_get_read_lock(FTFS_I(inode));

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	ret = ftfs_do_unlink(meta_dbt, txn, inode, sbi);
	if (ret) {
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
	} else {
		ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		COMMIT_JUMP_ON_CONFLICT(ret, retry);
		/* if (inode->i_size > HOT_FLUSH_THRESHOLD)
			ftfs_bstore_data_hot_flush(sbi->data_db,
				meta_key, 0,
				block_get_num_by_position(
					inode->i_size)); */
	}

	ftfs_put_read_lock(FTFS_I(inode));

no_delete:
	truncate_inode_pages(&inode->i_data, 0);

	invalidate_inode_buffers(inode);
	clear_inode(inode);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
}

// called when VFS wishes to free sb (unmount), sync southbound here
static void ftfs_put_super(struct super_block *sb)
{
	struct ftfs_sb_info *sbi = sb->s_fs_info;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	sync_filesystem(sb);

	sb->s_fs_info = NULL;

	ftfs_bstore_checkpoint(sbi->db_env);
	ftfs_bstore_env_close(sbi);

	free_percpu(sbi->s_ftfs_info);
	kfree(sbi);

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
}

static int ftfs_sync_fs(struct super_block *sb, int wait)
{
	//struct ftfs_sb_info *sbi = sb->s_fs_info;

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	//return ftfs_bstore_flush_log(sbi->db_env);
	return 0;
}

static int ftfs_dir_release(struct inode *inode, struct file *filp)
{
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif

#ifdef CALL_TRACE
	ftfs_error(__func__, "\n");
#endif
	if (filp->f_pos != 0 && filp->f_pos != 1) {
		//ftfs_error(__func__, "filep->fpos: %px\n", filp->f_pos);
		kfree((char *)filp->f_pos);
	}

#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif
	return 0;
}

static const struct address_space_operations ftfs_aops = {
	.readpage		= ftfs_readpage,
	.readpages		= ftfs_readpages,
	.writepage		= ftfs_writepage,
	.writepages		= ftfs_writepages,
	.write_begin		= ftfs_write_begin,
	.write_end		= ftfs_write_end,
	.launder_page		= ftfs_launder_page,
	.set_page_dirty = __set_page_dirty_nobuffers,
};

/*
static const struct file_operations ftfs_file_file_operations = {
	.llseek			= generic_file_llseek,
	.fsync			= ftfs_fsync,
	.read			= do_sync_read,
	.write			= do_sync_write,
	.aio_read		= generic_file_aio_read,
	.aio_write		= generic_file_aio_write,
	.mmap			= generic_file_mmap,
};
*/

static const struct file_operations ftfs_file_file_operations = {
	.llseek			= generic_file_llseek,
	.fsync			= ftfs_fsync,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.mmap			= generic_file_mmap,
};


static const struct file_operations ftfs_dir_file_operations = {
	.read			= generic_read_dir,
	.iterate		= ftfs_readdir,
	.fsync			= ftfs_fsync,
	.release		= ftfs_dir_release,
};

static const struct inode_operations ftfs_file_inode_operations = {
	.setattr		= ftfs_setattr
};

static const struct inode_operations ftfs_dir_inode_operations = {
	.create			= ftfs_create,
	.lookup			= ftfs_lookup,
	.link			= ftfs_link,
	.unlink			= ftfs_unlink,
	.symlink		= ftfs_symlink,
	.mkdir			= ftfs_mkdir,
	.rmdir			= ftfs_rmdir,
	.mknod			= ftfs_mknod,
	.rename			= ftfs_rename,
	.setattr		= ftfs_setattr,
	.getattr		= ftfs_getattr,
};

/*
static const struct inode_operations ftfs_symlink_inode_operations = {
	.setattr		= ftfs_setattr,
	.readlink		= generic_readlink,
	.follow_link		= ftfs_follow_link,
	.put_link		= ftfs_put_link,
};
*/

static const struct inode_operations ftfs_symlink_inode_operations = {
	.get_link		= ftfs_get_link,
	.setattr		= ftfs_setattr,
	.getattr		= ftfs_getattr,
};

static const struct inode_operations ftfs_special_inode_operations = {
	.setattr		= ftfs_setattr,
};

static const struct super_operations ftfs_super_ops = {
	.alloc_inode		= ftfs_alloc_inode,
	.destroy_inode		= ftfs_destroy_inode,
	.write_inode		= ftfs_write_inode,
	.evict_inode		= ftfs_evict_inode,
	.put_super		= ftfs_put_super,
	.sync_fs		= ftfs_sync_fs,
	.statfs			= ftfs_super_statfs,
};

/*
 * fill inode with meta_key, metadata from database and inode number
 */
static struct inode *
ftfs_setup_inode(struct super_block *sb, DBT *meta_dbt,
                 struct ftfs_metadata *meta)
{
	struct inode *i;
	struct ftfs_inode *ftfs_inode;
#ifdef CALL_TRACE_TIME
	struct time_break tb; 
	lightfs_tb_init(&tb);
	lightfs_tb_check(&tb);
#endif
	

	//local_irq_disable();
	if ((i = iget_locked(sb, meta->u.st.st_ino)) == NULL)
		return ERR_PTR(-ENOMEM);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	ftfs_inode = FTFS_I(i);
	if (!(i->i_state & I_NEW)) {
		//ftfs_error(__func__, "잘봐라\n");
		DBT *old_dbt = ftfs_get_write_lock(ftfs_inode);
		dbt_destroy(old_dbt);
		dbt_copy(old_dbt, meta_dbt);
		//ftfs_put_write_lock(ftfs_inode);
		return i;
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	BUG_ON(ftfs_inode->meta_dbt.data != NULL);
	dbt_copy(&ftfs_inode->meta_dbt, meta_dbt);
	init_rwsem(&ftfs_inode->key_lock);
	INIT_LIST_HEAD(&ftfs_inode->rename_locked);
	ftfs_inode->ftfs_flags = 0;
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	BUG_ON(meta->type != FTFS_METADATA_TYPE_NORMAL);
	i->i_rdev = meta->u.st.st_dev;
	i->i_mode = meta->u.st.st_mode;
	set_nlink(i, meta->u.st.st_nlink);
#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
	i->i_uid.val = meta->u.st.st_uid;
	i->i_gid.val = meta->u.st.st_gid;
#else
	//i->i_uid = meta->u.st.st_uid;
	//i->i_gid = meta->u.st.st_gid;
	//i->i_uid = from_kuid_munged(current_user_ns(), meta->u.st.st_uid);
	//i->i_gid = from_kgid_munged(current_user_ns(), meta->u.st.st_gid);
	i->i_uid = make_kuid(i->i_sb->s_user_ns, meta->u.st.st_uid);
	i->i_gid = make_kgid(i->i_sb->s_user_ns, meta->u.st.st_gid);
#endif
	i->i_size = meta->u.st.st_size;
	i->i_blocks = meta->u.st.st_blocks;
	TIME_T_TO_TIMESPEC(i->i_atime, meta->u.st.st_atime);
	TIME_T_TO_TIMESPEC(i->i_mtime, meta->u.st.st_mtime);
	TIME_T_TO_TIMESPEC(i->i_ctime, meta->u.st.st_ctime);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	if (S_ISREG(i->i_mode)) {
		/* Regular file */
		i->i_op = &ftfs_file_inode_operations;
		i->i_fop = &ftfs_file_file_operations;
		i->i_data.a_ops = &ftfs_aops;
	} else if (S_ISDIR(i->i_mode)) {
		/* Directory */
		i->i_op = &ftfs_dir_inode_operations;
		i->i_fop = &ftfs_dir_file_operations;
	} else if (S_ISLNK(i->i_mode)) {
		/* Sym link */
		i->i_op = &ftfs_symlink_inode_operations;
		i->i_data.a_ops = &ftfs_aops;
	} else if (S_ISCHR(i->i_mode) || S_ISBLK(i->i_mode) ||
	           S_ISFIFO(i->i_mode) || S_ISSOCK(i->i_mode)) {
		i->i_op = &ftfs_special_inode_operations;
		init_special_inode(i, i->i_mode, i->i_rdev); // duplicates work
	} else {
		BUG();
	}
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
#endif

	unlock_new_inode(i);
#ifdef CALL_TRACE_TIME
	lightfs_tb_check(&tb);
	lightfs_tb_print(__func__, &tb);
#endif

	//local_irq_enable();
	return i;
}


/*
 * fill in the superblock
 */
static int ftfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int ret;
	int cpu;
	ino_t ino = FTFS_INO_CUR;
	struct inode *root;
	struct ftfs_metadata meta;
	struct ftfs_sb_info *sbi;
	DBT root_dbt;
	DB_TXN *txn;

	// FTFS specific info
	ret = -ENOMEM;
	sbi = kzalloc(sizeof(struct ftfs_sb_info), GFP_NOIO);
	if (!sbi)
		goto err;

	sbi->s_ftfs_info = alloc_percpu(struct ftfs_info);
	if (!sbi->s_ftfs_info)
		goto err;

	sb->s_fs_info = sbi;
	sb_set_blocksize(sb, FTFS_BSTORE_BLOCKSIZE);
	sb->s_op = &ftfs_super_ops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;


	ret = ftfs_bstore_env_open(sbi);
	if (ret) {
		goto err;
	}

	TXN_GOTO_LABEL(retry);
	ftfs_bstore_txn_begin(sbi->db_env, NULL, &txn, TXN_MAY_WRITE);
	dbt_setup(&root_dbt, &root_meta_key, SIZEOF_CIRCLE_ROOT_META_KEY);
	ret = ftfs_bstore_meta_get(sbi->meta_db, &root_dbt, txn, &meta);
	ftfs_error(__func__, "lookup - fill super\n");
	if (ret) {
		if (ret == -ENOENT) {
			ftfs_setup_metadata(&meta, 0755 | S_IFDIR, 0, 0,
			                    FTFS_ROOT_INO);
			ret = ftfs_bstore_meta_put(sbi->meta_db,
			                           &root_dbt,
			                           txn, &meta);
		}
		if (ret) {
			DBOP_JUMP_ON_CONFLICT(ret, retry);
			ftfs_bstore_txn_abort(txn);
			goto err;
		}
	}
	/*
	ret = ftfs_bstore_get_ino(sbi->meta_db, txn, &ino);
	if (ret) {
db_op_err:
		DBOP_JUMP_ON_CONFLICT(ret, retry);
		ftfs_bstore_txn_abort(txn);
		goto err;
	} 
	*/
	ret = ftfs_bstore_txn_commit(txn, DB_TXN_SYNC);
	COMMIT_JUMP_ON_CONFLICT(ret, retry);

	sbi->s_nr_cpus = 0;
	for_each_possible_cpu(cpu) {
		//(per_cpu_ptr(sbi->s_ftfs_info, cpu))->next_ino = ino + cpu;
		//(per_cpu_ptr(sbi->s_ftfs_info, cpu))->max_ino = ino;
		(per_cpu_ptr(sbi->s_ftfs_info, cpu))->next_ino = ino + cpu;
		(per_cpu_ptr(sbi->s_ftfs_info, cpu))->max_ino = FTFS_INO_MAX;
		sbi->s_nr_cpus++;
	}

	root = ftfs_setup_inode(sb, &root_dbt, &meta);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto err_close;
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		ret = -EINVAL;
		goto err_close;
	}

	return 0;

err_close:
	ftfs_bstore_env_close(sbi);
err:
	if (sbi) {
		if (sbi->s_ftfs_info)
			free_percpu(sbi->s_ftfs_info);
		kfree(sbi);
	}
	return ret;
}

/*
 * mount ftfs, call kernel util mount_bdev
 * actual work of ftfs is done in ftfs_fill_super
 */
static struct dentry *ftfs_mount(struct file_system_type *fs_type, int flags,
                                 const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ftfs_fill_super);
}

static void ftfs_kill_sb(struct super_block *sb)
{
	sync_filesystem(sb);
	kill_block_super(sb);
}

static struct file_system_type ftfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ftfs",
	.mount		= ftfs_mount,
	.kill_sb	= ftfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};

int init_ftfs_fs(void)
{
	int ret;

	ftfs_inode_cachep =
		kmem_cache_create("ftfs_i",
		                  sizeof(struct ftfs_inode), 0,
		                  SLAB_RECLAIM_ACCOUNT,
		                  ftfs_i_init_once);
	if (!ftfs_inode_cachep) {
		printk(KERN_ERR "FTFS ERROR: Failed to initialize inode cache.\n");
		ret = -ENOMEM;
		goto out;
	}

	ftfs_writepages_cachep =
		kmem_cache_create("ftfs_wp",
		                  sizeof(struct ftfs_wp_node), 0,
		                  SLAB_RECLAIM_ACCOUNT,
		                  NULL);
	if (!ftfs_writepages_cachep) {
		printk(KERN_ERR "FTFS ERROR: Failed to initialize write page vec cache.\n");
		ret = -ENOMEM;
		goto out_free_inode_cachep;
	}

	ret = register_filesystem(&ftfs_fs_type);
	if (ret) {
		printk(KERN_ERR "FTFS ERROR: Failed to register filesystem\n");
		goto out_free_writepages_cachep;
	}

	return 0;

out_free_writepages_cachep:
	kmem_cache_destroy(ftfs_writepages_cachep);
out_free_inode_cachep:
	kmem_cache_destroy(ftfs_inode_cachep);
out:
	return ret;
}

void exit_ftfs_fs(void)
{
	unregister_filesystem(&ftfs_fs_type);

	kmem_cache_destroy(ftfs_writepages_cachep);

	kmem_cache_destroy(ftfs_inode_cachep);
}
