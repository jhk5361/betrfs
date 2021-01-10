#include <linux/kernel.h>
#include <linux/slab.h>

#include "lightfs.h"
#include "ftfs_fs.h"
#include "lightfs_db_env.h"
#include "lightfs_db.h"
#include "lightfs_cache.h"
#include "lightfs_reada.h"

size_t db_cachesize;

#define DB_ENV_PATH "/db"
#define DATA_DB_NAME "ftfs_data"
#define META_DB_NAME "ftfs_meta"

// XXX: delete these 2 variables once southbound dependency is solved
static DB_ENV *XXX_db_env;
static DB *XXX_data_db;
static DB *XXX_meta_db;
static DB *XXX_cache_db;

static char ino_key[] = "m\x00\x00\x00\x00\x00\x00\x00\x00next_ino";

static char meta_desc_buf[] = "meta";
static char data_desc_buf[] = "data";
static DBT meta_desc = {
	.data = meta_desc_buf,
	.size = sizeof(meta_desc_buf),
	.ulen = sizeof(meta_desc_buf),
	.flags = DB_DBT_USERMEM,
};
static DBT data_desc = {
	.data = data_desc_buf,
	.size = sizeof(data_desc_buf),
	.ulen = sizeof(data_desc_buf),
	.flags = DB_DBT_USERMEM,
};

extern int
alloc_data_dbt_from_meta_dbt(DBT *data_dbt, DBT *meta_dbt, uint64_t block_num);

extern int
alloc_child_meta_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt, const char *name);

extern void
copy_data_dbt_from_inode(DBT *data_dbt, struct inode *inode, uint64_t block_num);

extern int
alloc_data_dbt_from_inode(DBT *data_dbt, struct inode *inode, uint64_t block_num);

extern int
alloc_data_dbt_from_ino(DBT *data_dbt, uint64_t ino, uint64_t block_num);

extern int
alloc_child_meta_dbt_from_inode(DBT *dbt, struct inode *dir, const char *name);

extern void
copy_data_dbt_from_meta_dbt(DBT *data_dbt, DBT *meta_dbt, uint64_t block_num);

extern int
alloc_meta_dbt_prefix(DBT *prefix_dbt, DBT *meta_dbt);

extern void copy_meta_dbt_from_ino(DBT *dbt, uint64_t ino);

static void
copy_child_meta_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt, const char *name)
{
	char *parent_key = parent_dbt->data;
	char *meta_key = dbt->data;
	size_t size;
	char *last_slash;

	if ((ftfs_key_path(parent_key))[0] == '\0')
		size = parent_dbt->size + strlen(name) + 2;
	else
		size = parent_dbt->size + strlen(name) + 1;
	BUG_ON(size > dbt->ulen);
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
		//ftfs_error(__func__, "the key path=%s, parent=%s\n", ftfs_key_path(meta_key), ftfs_key_path(parent_key));
	}

	dbt->size = size;
}

static void
copy_child_data_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt,
                                  const char *name, uint64_t block_num)
{
	char *parent_key = parent_dbt->data;
	char *data_key = dbt->data;
	size_t size;
	char *last_slash;

	if ((ftfs_key_path(parent_key))[0] == '\0')
		size = parent_dbt->size + strlen(name) + 2;
	else
		size = parent_dbt->size + strlen(name) + 1;
	size += DATA_META_KEY_SIZE_DIFF;
	BUG_ON(size > dbt->ulen);
	ftfs_key_set_magic(data_key, DATA_KEY_MAGIC);
	ftfs_key_copy_ino(data_key, parent_key);
	ftfs_data_key_set_blocknum(data_key, size, block_num);
	if ((ftfs_key_path(parent_key))[0] == '\0') {
		sprintf(ftfs_key_path(data_key), "\x01\x01%s", name);
	} else {
		last_slash = strrchr(ftfs_key_path(parent_key), '\x01');
		BUG_ON(last_slash == NULL);
		memcpy(ftfs_key_path(data_key), ftfs_key_path(parent_key),
		       last_slash - ftfs_key_path(parent_key));
		sprintf(ftfs_key_path(data_key) + (last_slash - ftfs_key_path(parent_key)),
		        "%s\x01\x01%s", last_slash + 1, name);
	}

	dbt->size = size;
}

static void
copy_child_meta_dbt_from_inode(DBT *dbt, struct inode *dir, const char *name)
{
	char *meta_key = dbt->data;
	size_t size;
	uint64_t parent_ino = dir->i_ino;

	size = PATH_POS + strlen(name) + 1;
	BUG_ON(size > dbt->ulen);
	ftfs_key_set_magic(meta_key, META_KEY_MAGIC);
	ftfs_key_set_ino(meta_key, parent_ino);
	sprintf(ftfs_key_path(meta_key), "%s", name);

	dbt->size = size;
}

#if 0
static void
copy_child_data_dbt_from_inode(DBT *data_dbt, struct inode *inode,
                                  const char *name, uint64_t block_num)
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
#endif

static inline void
copy_subtree_max_meta_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt)
{
	copy_child_meta_dbt_from_meta_dbt(dbt, parent_dbt, "");
	*((char *)(dbt->data + dbt->size - 2)) = '\xff';
	//ftfs_error(__func__, "the key path=%s after\n", ftfs_key_path(dbt->data));
}

static inline void
copy_subtree_max_data_dbt_from_meta_dbt(DBT *dbt, DBT *parent_dbt)
{
	copy_child_data_dbt_from_meta_dbt(dbt, parent_dbt, "", 0);
	*((char *)(dbt->data + dbt->size - sizeof(uint64_t) - 2)) = '\xff';
}

static void
copy_meta_dbt_movdir(const DBT *old_prefix_dbt, const DBT *new_prefix_dbt,
                     const DBT *old_dbt, DBT *new_dbt)
{
	char *new_prefix_key = new_prefix_dbt->data;
	char *old_key = old_dbt->data;
	char *new_key = new_dbt->data;
	size_t size;

	size = old_dbt->size - old_prefix_dbt->size + new_prefix_dbt->size;
	BUG_ON(size > new_dbt->ulen);
	ftfs_key_set_magic(new_key, META_KEY_MAGIC);
	ftfs_key_copy_ino(new_key, new_prefix_key);
	//trace_printk("new prefix key=%s, old prefix=%s\n", ftfs_key_path(new_prefix_key), ftfs_key_path(old_prefix_dbt->data));
	sprintf(ftfs_key_path(new_key), "%s%s", ftfs_key_path(new_prefix_key),
	        old_key + old_prefix_dbt->size - 1);

	new_dbt->size = size;
}

static void
copy_data_dbt_movdir(const DBT *old_prefix_dbt, const DBT *new_prefix_dbt,
                     const DBT *old_dbt, DBT *new_dbt)
{
	char *new_prefix_key = new_prefix_dbt->data;
	char *old_key = old_dbt->data;
	char *new_key = new_dbt->data;
	size_t size;

	size = old_dbt->size - old_prefix_dbt->size + new_prefix_dbt->size;
	BUG_ON(size > new_dbt->ulen);
	ftfs_key_set_magic(new_key, DATA_KEY_MAGIC);
	ftfs_key_copy_ino(new_key, new_prefix_key);
	sprintf(ftfs_key_path(new_key), "%s%s", ftfs_key_path(new_prefix_key),
	        old_key + old_prefix_dbt->size - 1);
	ftfs_data_key_set_blocknum(new_key, size,
		ftfs_data_key_get_blocknum(old_key, old_dbt->size));

	new_dbt->size = size;
}

#if 0
static int
meta_key_is_child_of_meta_key(char *child_key, char *parent_key)
{
	//print_key(__func__, child_key, 10);
	//print_key(__func__, parent_key, 10);
	if (ftfs_key_get_ino(child_key) != ftfs_key_get_ino(parent_key))
		return 0;
	else
		return 1;
}
#endif

static int
meta_key_is_child_of_ino(char *child_key, ino_t ino)
{
	if (ftfs_key_get_ino(child_key) != ino)
		return 0;
	else
		return 1;
}

// get the ino_num counting stored in meta_db
// for a brand new DB, it will init ino_num in meta_db (so it may write)
int ftfs_bstore_get_ino(DB *meta_db, DB_TXN *txn, ino_t *ino)
{
	int ret;
	DBT ino_key_dbt, ino_val_dbt;

	dbt_setup(&ino_key_dbt, ino_key, sizeof(ino_key));
	dbt_setup(&ino_val_dbt, ino, sizeof(*ino));

	ret = meta_db->get(meta_db, txn, &ino_key_dbt,
	                   &ino_val_dbt, LIGHTFS_META_GET);
	if (ret == DB_NOTFOUND) {
		*ino = FTFS_ROOT_INO + 1;
		ret = meta_db->put(meta_db, txn, &ino_key_dbt,
		                   &ino_val_dbt, LIGHTFS_META_SET);
	}

	return ret;
}

// get the ino_num counting in meta_db
// if it is smaller than our ino, update that with our ino
int ftfs_bstore_update_ino(DB *meta_db, DB_TXN *txn, ino_t ino)
{
	int ret;
	ino_t curr_ino;
	DBT ino_key_dbt, ino_val_dbt;

	dbt_setup(&ino_key_dbt, ino_key, sizeof(ino_key));
	dbt_setup(&ino_val_dbt, &curr_ino, sizeof(curr_ino));

	ret = meta_db->get(meta_db, txn, &ino_key_dbt,
	                   &ino_val_dbt, LIGHTFS_META_GET);
	if (!ret && ino > curr_ino) {
		curr_ino = ino;
		ret = meta_db->put(meta_db, txn, &ino_key_dbt,
		                   &ino_val_dbt, LIGHTFS_META_SET);
	}

	return ret;
}

static int env_keycmp(DB *DB, DBT const *a, DBT const *b)
{
	int r;
	uint32_t alen, blen;
	alen = a->size;
	blen = b->size;
	if (alen < blen) {
		r = memcmp(a->data, b->data, alen);
		if (r)
			return r;
		return -1;
	} else if (alen > blen) {
		r = memcmp(a->data, b->data, blen);
		if (r)
			return r;
		return 1;
	}
	// alen == blen
	return memcmp(a->data, b->data, alen);
}

static int
env_keyrename(const DBT *old_prefix, const DBT *new_prefix, const DBT *old_dbt,
              void (*set_key)(const DBT *new_key, void *set_extra),
              void *set_extra)
{
	size_t new_len;
	void *new_key;
	DBT new_key_dbt;
	char *old_prefix_key = old_prefix->data;
	char *old_key = old_dbt->data;

	if (old_prefix->size > old_dbt->size)
		return -EINVAL;

	//This may happen when a kupsert was saved and added to the ancester
	//  list right before a cleaner thread kicks in and chooses to flush
	//  down this kupsert msg.... so the kupsert saved in the ancesters is
	//  stalei. This is possible because the cleaner threads do not lock
	//  hand-over-hand from the root to the leaf, instead it is done in the
	//  layer of cachetable which maintains a list of pairs and m_cleaner head
	if (!key_is_in_subtree_of_prefix(old_key, old_prefix_key, old_prefix->size) &&
	    !key_is_same_of_key(old_key, old_prefix_key))
		return 0;

	new_len = old_dbt->size - old_prefix->size + new_prefix->size;
	new_key = kmalloc(new_len, GFP_NOIO);
	if (!new_key)
		return -ENOMEM;

	dbt_setup_buf(&new_key_dbt, new_key, new_len);
	if (IS_META_KEY_DBT(old_dbt))
		copy_meta_dbt_movdir(old_prefix, new_prefix,
		                     old_dbt, &new_key_dbt);
	else
		copy_data_dbt_movdir(old_prefix, new_prefix,
		                     old_dbt, &new_key_dbt);

	set_key(&new_key_dbt, set_extra);
	kfree(new_key);

	return 0;
}

static void env_keyprint(const DBT *key, bool is_trace_printable)
{
	if (key == NULL) {
		if(is_trace_printable) {
			trace_printk(KERN_INFO "ftfs_env_keypnt: key == NULL\n");
		} else {
			printk(KERN_INFO "ftfs_env_keypnt: key == NULL\n");
		}
	}
	else if (key->data == NULL) {
		if(is_trace_printable) {
			trace_printk(KERN_INFO "ftfs_env_keypnt: key->data == NULL\n");
		} else {

			printk(KERN_INFO "ftfs_env_keypnt: key->data == NULL\n");
		}
	}
	else if (IS_META_KEY_DBT(key)) {
		char *meta_key = key->data;
		if(is_trace_printable) {
			trace_printk(KERN_INFO "ftfs_env_keypnt: meta_key (%llu)%s, size=%u\n",
		        	         ftfs_key_get_ino(meta_key),
		                	 ftfs_key_path(meta_key),
					 key->size);
		} else {

			printk(KERN_INFO "ftfs_env_keypnt: meta_key (%llu)%s\n, size=%u\n",
		        	         ftfs_key_get_ino(meta_key),
		                	 ftfs_key_path(meta_key),
					 key->size);
		}
	} else if (IS_DATA_KEY_DBT(key)) {
		char *data_key = key->data;
		if(is_trace_printable) {
			trace_printk(KERN_INFO "ftfs_env_keypnt: data_key (%llu)%s:%llu\n",
		        	         ftfs_key_get_ino(data_key),
		                	 ftfs_key_path(data_key),
		                 	ftfs_data_key_get_blocknum(data_key, key->size));
		} else {

			printk(KERN_INFO "ftfs_env_keypnt: data_key (%llu)%s:%llu\n",
		        	         ftfs_key_get_ino(data_key),
		                	 ftfs_key_path(data_key),
		                 	ftfs_data_key_get_blocknum(data_key, key->size));
		}
	} else {
		BUG();
	}
}

static struct toku_db_key_operations ftfs_key_ops = {
	.keycmp       = env_keycmp,
	.keypfsplit   = NULL,
	.keyrename    = env_keyrename,
	.keyprint     = env_keyprint,
	.keylift      = NULL,
	.keyliftkey   = NULL,
	.keyunliftkey = NULL,
};

/*
 * block update callback info
 * set value in [offset, offset + size) to buf
 */
struct block_update_cb_info {
	loff_t offset;
	size_t size;
	char buf[];
};

static int
env_update_cb(DB *db, const DBT *key, const DBT *old_val, const DBT *extra,
              void (*set_val)(const DBT *newval, void *set_extra),
              void *set_extra)
{
	DBT val;
	size_t newval_size;
	void *newval;
	const struct block_update_cb_info *info = extra->data;

	if (info->size == 0) {
		// info->size == 0 means truncate
		if (!old_val) {
			newval_size = 0;
			newval = NULL;
		} else {
			newval_size = info->offset;
			if (old_val->size < newval_size) {
				// this means we should keep the old val
				// can we just forget about set_val in this case?
				// idk, to be safe, I did set_val here
				newval_size = old_val->size;
			}
			// now we guaranteed old_val->size >= newval_size
			newval = kmalloc(newval_size, GFP_NOIO);
			if (!newval)
				return -ENOMEM;
			memcpy(newval, old_val->data, newval_size);
		}
	} else {
		// update [info->offset, info->offset + info->size) to info->buf
		newval_size = info->offset + info->size;
		if (old_val && old_val->size > newval_size)
			newval_size = old_val->size;
		newval = kmalloc(newval_size, GFP_NOIO);
		if (!newval)
			return -ENOMEM;
		if (old_val) {
			// copy old val here
			memcpy(newval, old_val->data, old_val->size);
			// fill the place that is not covered by old_val
			//  nor info->buff with 0
			if (info->offset > old_val->size)
				memset(newval + old_val->size, 0,
				       info->offset - old_val->size);
		} else {
			if (info->offset > 0)
				memset(newval, 0, info->offset);
		}
		memcpy(newval + info->offset, info->buf, info->size);
	}

	dbt_setup(&val, newval, newval_size);
	set_val(&val, set_extra);
	kfree(newval);

	return 0;
}

/*
 * Set up DB environment.
 */
int ftfs_bstore_env_open(struct ftfs_sb_info *sbi)
{
	int r;
	uint32_t db_env_flags, db_flags;
	uint32_t giga_bytes, bytes;
	DB_TXN *txn = NULL;
	DB_ENV *db_env;

	BUG_ON(sbi->db_env || sbi->data_db || sbi->meta_db);

	r = lightfs_db_env_create(&sbi->db_env, 0);
	if (r != 0) {
		if (r == TOKUDB_HUGE_PAGES_ENABLED)
			printk(KERN_ERR "Failed to create the TokuDB environment because Transparent Huge Pages (THP) are enabled.  Please disable THP following the instructions at https://docs.mongodb.com/manual/tutorial/transparent-huge-pages/.  You may set the parameter to madvise or never. (errno %d)\n", r);
		else
			printk(KERN_ERR "Failed to create the TokuDB environment, errno %d\n", r);
		goto err;
	}

	db_env = sbi->db_env;

	giga_bytes = db_cachesize / (1L << 30);
	bytes = db_cachesize % (1L << 30);
	r = db_env->set_cachesize(db_env, giga_bytes, bytes, 1);
	if (r != 0)
		goto err;
	r = db_env->set_key_ops(db_env, &ftfs_key_ops);
	if (r != 0)
		goto err;

	db_env->set_update(db_env, env_update_cb);

	db_env_flags = DB_CREATE | DB_PRIVATE | DB_THREAD | DB_INIT_MPOOL |
	               DB_INIT_LOCK | DB_RECOVER | DB_INIT_LOG | DB_INIT_TXN;

	r = db_env->open(db_env, DB_ENV_PATH, db_env_flags, 0755);
	if (r) {
		r = -ENOENT;
		goto err;
	}

	db_flags = DB_CREATE | DB_THREAD;
	r = lightfs_db_create(&sbi->data_db, db_env, 0);
	if (r)
		goto err_close_env;
	r = lightfs_db_create(&sbi->meta_db, db_env, 0);
	if (r)
		goto err_close_env;

	r = lightfs_cache_create(&sbi->cache_db, db_env, 0);
	if (r)
		goto err_close_env;

	r = ftfs_bstore_txn_begin(db_env, NULL, &txn, TXN_READONLY);
	if (r)
		goto err_close_env;
	r = sbi->data_db->open(sbi->data_db, txn, DATA_DB_NAME, NULL,
	                       DB_BTREE, db_flags, 0644);
	if (r) {
		ftfs_bstore_txn_abort(txn);
		goto err_close_env;
	}
	r = sbi->data_db->change_descriptor(sbi->data_db, txn, &data_desc, DB_UPDATE_CMP_DESCRIPTOR);
	if (r) {
		ftfs_bstore_txn_abort(txn);
		goto err_close_env;
	}
	r = sbi->meta_db->open(sbi->meta_db, txn, META_DB_NAME, NULL,
	                       DB_BTREE, db_flags, 0644);
	if (r) {
		ftfs_bstore_txn_abort(txn);
		goto err_close_env;
	}
	r = sbi->meta_db->change_descriptor(sbi->meta_db, txn, &meta_desc, DB_UPDATE_CMP_DESCRIPTOR);
	if (r) {
		ftfs_bstore_txn_abort(txn);
		goto err_close_env;
	}

	r = ftfs_bstore_txn_commit(txn, DB_TXN_SYNC);
	if (r)
		goto err_close_env;

	/* set the cleaning and checkpointing thread periods */
	db_env_flags = 60; /* 60 s */
	r = db_env->checkpointing_set_period(db_env, db_env_flags);
	if (r)
		goto err_close;
	db_env_flags = 1; /* 1s */
	r = db_env->cleaner_set_period(db_env, db_env_flags);
	if (r)
		goto err_close;
	db_env_flags = 1000; /* 1000 ms */
	db_env->change_fsync_log_period(db_env, db_env_flags);

	XXX_db_env = sbi->db_env;
	XXX_data_db = sbi->data_db;
	XXX_meta_db = sbi->meta_db;
	XXX_cache_db = sbi->cache_db;

	return 0;

err_close:
	sbi->data_db->close(sbi->data_db, 0);
	sbi->meta_db->close(sbi->meta_db, 0);
	sbi->cache_db->close(sbi->cache_db, 0);
err_close_env:
	db_env->close(db_env, 0);
err:
	return r;
}

/*
 * Close DB environment
 */
int ftfs_bstore_env_close(struct ftfs_sb_info *sbi)
{
	int ret;

	ret = ftfs_bstore_flush_log(sbi->db_env);
	if (ret)
		goto out;
	BUG_ON(sbi->data_db == NULL || sbi->meta_db == NULL || sbi->db_env == NULL || sbi->cache_db == NULL);

	ret = sbi->cache_db->close(sbi->cache_db, 0);
	BUG_ON(ret);
	sbi->cache_db = NULL;

	ret = sbi->data_db->close(sbi->data_db, 0);
	BUG_ON(ret);
	sbi->data_db = NULL;

	ret = sbi->meta_db->close(sbi->meta_db, 0);
	BUG_ON(ret);
	sbi->meta_db = NULL;

	ret = sbi->db_env->close(sbi->db_env, 0);
	BUG_ON(ret != 0);
	sbi->db_env = 0;

	XXX_db_env = NULL;
	XXX_data_db = NULL;
	XXX_meta_db = NULL;

out:
	return 0;
}

int ftfs_bstore_meta_get_tmp(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
                         struct ftfs_metadata *metadata)
{
	int ret = 0;
	DBT value;

	dbt_setup(&value, metadata, sizeof(*metadata));
	if (sizeof(*metadata) != 152)
		pr_info("메타 사이즈: %ld\n", sizeof(*metadata));

	//print_key(__func__, meta_dbt->data, meta_dbt->size);
	ret = XXX_cache_db->get(XXX_cache_db, NULL, meta_dbt, &value, 0);

	if (ret == DB_NOTFOUND) {
		ret = -ENOENT;
	} else if (ret == DB_FOUND_FREE) {
		ret = 0;
		pr_info("뭐여...?!\n");	
	}

	return ret;
}

int ftfs_bstore_meta_get(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
                         struct ftfs_metadata *metadata)
{
	int ret;
	static int miss = 0;
	DBT value, tmp;

#ifdef BETR
	return ftfs_bstore_meta_get_tmp(meta_db, meta_dbt, txn, metadata);
#endif

	dbt_setup(&value, metadata, sizeof(*metadata));

	//print_key(__func__, meta_dbt->data, meta_dbt->size);
	ret = XXX_cache_db->get(XXX_cache_db, NULL, meta_dbt, &value, 0);

	if (ret == DB_NOTFOUND) {
		ret = -ENOENT;
	} else if (ret == DB_FOUND_FREE) {
			dbt_setup(&tmp, metadata, sizeof(*metadata));
			//ret = meta_db->get(meta_db, txn, meta_dbt, &tmp, LIGHTFS_META_GET);
			//if ( ((miss++) % MISS_RATE) == 0)
				//ret = meta_db->get(meta_db, txn, meta_dbt, &tmp, LIGHTFS_META_GET);
			//else 
				ret = 0;
	}

	return ret;
}

int ftfs_bstore_meta_put_tmp(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
                         struct ftfs_metadata *metadata)
{
	DBT value;

	dbt_setup(&value, metadata, sizeof(*metadata));

	return XXX_cache_db->put(XXX_cache_db, NULL, meta_dbt, &value, 0);
}


int ftfs_bstore_meta_put(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
                         struct ftfs_metadata *metadata)
{
	DBT value;

#ifdef BETR
	return ftfs_bstore_meta_put_tmp(meta_db, meta_dbt, txn, metadata);
#endif


	dbt_setup(&value, metadata, sizeof(*metadata));

	XXX_cache_db->put(XXX_cache_db, NULL, meta_dbt, &value, 0);

	return meta_db->put(meta_db, txn, meta_dbt, &value, LIGHTFS_META_SET);
}

int ftfs_bstore_meta_sync_put(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
						 struct ftfs_metadata *metadata)
{
	DBT value;

	dbt_setup(&value, metadata, sizeof(*metadata));

	XXX_cache_db->put(XXX_cache_db, NULL, meta_dbt, &value, 0);

	//return meta_db->sync_put(meta_db, txn, meta_dbt, &value, LIGHTFS_META_SYNC_SET);
	return meta_db->sync_put(meta_db, txn, meta_dbt, &value, LIGHTFS_META_SET);
}


int ftfs_bstore_meta_del(DB *meta_db, DBT *meta_dbt, DB_TXN *txn, bool is_weak_del)
{
	if (is_weak_del) {
		XXX_cache_db->weak_del(XXX_cache_db, NULL, meta_dbt, 0);
		return 0;
	} else {
		XXX_cache_db->del(XXX_cache_db, NULL, meta_dbt, 0);
	}
	return meta_db->del(meta_db, txn, meta_dbt, LIGHTFS_META_DEL);
}

static unsigned char filetype_table[] = {
	DT_UNKNOWN, DT_FIFO, DT_CHR, DT_UNKNOWN,
	DT_DIR, DT_UNKNOWN, DT_BLK, DT_UNKNOWN,
	DT_REG, DT_UNKNOWN, DT_LNK, DT_UNKNOWN,
	DT_SOCK, DT_UNKNOWN, DT_WHT, DT_UNKNOWN
};

#define ftfs_get_type(mode) filetype_table[(mode >> 12) & 15]

int ftfs_bstore_meta_readdir(DB *meta_db, DBT *meta_dbt, DB_TXN *txn,
                             struct dir_context *ctx, struct inode *inode, struct readdir_ctx *dir_ctx)
{
	int ret, r;
	char *child_meta_key;
	struct ftfs_metadata meta;
	DBT child_meta_dbt, metadata_dbt;
	DBC *cursor;
	char *name;
	u64 ino;
	unsigned type;
	char indirect_meta_key[SIZEOF_CIRCLE_ROOT_META_KEY];
	DBT indirect_meta_dbt;

	ftfs_error(__func__, "ctx->pos = %d\n", ctx->pos);

	if (ctx->pos == 2) {
		child_meta_key = kmalloc(META_KEY_MAX_LEN, GFP_NOIO);
		if (child_meta_key == NULL)
			return -ENOMEM;
		dbt_setup_buf(&child_meta_dbt, child_meta_key, META_KEY_MAX_LEN);
		// KOO:key
		//copy_child_meta_dbt_from_meta_dbt(&child_meta_dbt, meta_dbt, "");
		copy_child_meta_dbt_from_inode(&child_meta_dbt, inode, "\x01");
		//ctx->pos = (loff_t)(child_meta_key);
		dir_ctx->pos = (loff_t)(child_meta_key);
		ctx->pos = (loff_t)(dir_ctx);
	} else {
		child_meta_key = (char *)dir_ctx->pos;
		dbt_setup(&child_meta_dbt, child_meta_key, META_KEY_MAX_LEN);
		child_meta_dbt.size = SIZEOF_META_KEY(child_meta_key);
	}

	dbt_setup(&metadata_dbt, &meta, sizeof(meta));
	dbt_setup_buf(&indirect_meta_dbt, indirect_meta_key,
	              SIZEOF_CIRCLE_ROOT_META_KEY);
	//ret = meta_db->cursor(meta_db, txn, &cursor, LIGHTFS_META_CURSOR);
	//if (ret)
	//	goto out;
	cursor = dir_ctx->cursor;
	txn = dir_ctx->txn;
		
	ftfs_error(__func__, "bstore!!!! dir_ctx: %px, dir_ctx->pos: %d, dir->cursor: %px, dir->txn: %px\n", dir_ctx, dir_ctx->pos, dir_ctx->cursor, dir_ctx->txn);

	r = cursor->c_get(cursor, &child_meta_dbt, &metadata_dbt, DB_SET_RANGE);
	while (!r) {
		//if (!meta_key_is_child_of_meta_key(child_meta_key, meta_dbt->data)) {
		//print_key(__func__, child_meta_key, child_meta_dbt.size);
		if (!meta_key_is_child_of_ino(child_meta_key, inode->i_ino)) {
			kfree(child_meta_key);
			dir_ctx->pos = 3;
			break;
		}
		if (meta.type == FTFS_METADATA_TYPE_REDIRECT) {
			ftfs_error(__func__, "아니지???\n");
			copy_meta_dbt_from_ino(&indirect_meta_dbt, meta.u.ino);
			r = ftfs_bstore_meta_get(meta_db, &indirect_meta_dbt,
			                         txn, &meta);
			if (r)
				break;
		}
		ino = meta.u.st.st_ino;
		type = ftfs_get_type(meta.u.st.st_mode);
		//name = strrchr(ftfs_key_path(child_meta_key), '\x01') + 1;
		name = ftfs_key_path(child_meta_key);
		ftfs_error(__func__, "child_meta_key name:%s, len = %d, ino: %d, type: %d\n", name, strlen(name), ino, type);
		if (!(ret = dir_emit(ctx, name, strlen(name), ino, type))) {
			ftfs_error(__func__, "뭐다냐???\n");
			break;
		}

		r = cursor->c_get(cursor, &child_meta_dbt, &metadata_dbt,
		                  DB_NEXT);
	}

	if (r == DB_NOTFOUND) {
		ftfs_error(__func__, "못찾았다고?????\n");
		kfree(child_meta_key);
		dir_ctx->pos = 3;
		r = 0;
	}

	//cursor->c_close(cursor);

	if (r)
		ret = r;

out:
	return ret;
}

int ftfs_bstore_get(DB *data_db, DBT *data_dbt, DB_TXN *txn, void *buf, struct inode *inode)
{
	int ret;
	DBT value;
	loff_t size = i_size_read(inode);
	char *data_key = data_dbt->data;
	size_t block_off = block_get_off_by_position(size);
	uint64_t block_num = ftfs_get_block_num_by_size(size);
	

	dbt_setup(&value, buf, FTFS_BSTORE_BLOCKSIZE);

	//TODO: memset 처리
	ret = data_db->get(data_db, txn, data_dbt, &value, LIGHTFS_DATA_GET);
	//if (!ret && value.size < FTFS_BSTORE_BLOCKSIZE)
	if (!ret && (ftfs_data_key_get_blocknum(data_key, data_dbt->size) == block_num) && block_off && (block_off < FTFS_BSTORE_BLOCKSIZE)) {
		//memset(buf + value.size, 0, FTFS_BSTORE_BLOCKSIZE - value.size);
		memset(buf + block_off, 0, FTFS_BSTORE_BLOCKSIZE - block_off);
	}
	if (ret == DB_NOTFOUND)
		ret = -ENOENT;

	return ret;
}

// size of buf must be FTFS_BLOCK_SIZE
int ftfs_bstore_put(DB *data_db, DBT *data_dbt, DB_TXN *txn,
                    const void *buf, size_t len, int is_seq)
{
	int ret;
	DBT value;

	dbt_setup(&value, buf, len);

	ret = is_seq ?
	      data_db->seq_put(data_db, txn, data_dbt, &value, LIGHTFS_DATA_SEQ_SET) :
	      data_db->put(data_db, txn, data_dbt, &value, LIGHTFS_DATA_SET);

	return ret;
}

int ftfs_bstore_put_page(DB *data_db, DBT *data_dbt, DB_TXN *txn,
                    struct page *page, size_t len, int is_seq)
{
	int ret;
	DBT value;

	dbt_setup(&value, page, len);

	ret = data_db->put(data_db, txn, data_dbt, &value, LIGHTFS_DATA_SET_WB);

	return ret;
}


int ftfs_bstore_update(DB *data_db, DBT *data_dbt, DB_TXN *txn,
                       const void *buf, size_t size, loff_t offset)
{
	int ret;
	DBT value;

	dbt_setup(&value, buf, size);

	ret = data_db->update(data_db, txn, data_dbt, &value, offset, LIGHTFS_DATA_UPDATE);

	return ret;
}

// delete all blocks that is beyond new_num
//  if offset == 0, delete block new_num as well
//  otherwise, truncate block new_num to size offset
int ftfs_bstore_trunc(DB *data_db, DBT *meta_dbt,
                      DB_TXN *_txn, uint64_t new_num, uint64_t offset, struct inode *inode)
{
	int ret;
	DBT min_data_key_dbt, max_data_key_dbt, value;
	loff_t size = i_size_read(inode);
	uint64_t last_block_num = ftfs_get_block_num_by_size(size);
	uint64_t current_block_num, total_block_num, transfering_block_cnt;
	//bool new_txn = 0;
	DB_TXN *txn = _txn;
	if (new_num == 0) {
		current_block_num = 1;
	} else {
		current_block_num = (offset == 0) ? new_num : (new_num + 1);
	}



	//ftfs_error(__func__, "안돼 씨바알\n");
	//KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&min_data_key_dbt, meta_dbt,
	ret = alloc_data_dbt_from_inode(&min_data_key_dbt, inode,
		current_block_num);
	if (ret)
		return ret;
	//KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&max_data_key_dbt, meta_dbt, FTFS_UINT64_MAX);
	//ret = alloc_data_dbt_from_inode(&max_data_key_dbt, inode, FTFS_UINT64_MAX);
	ret = alloc_data_dbt_from_inode(&max_data_key_dbt, inode, current_block_num);
	if (ret) {
		dbt_destroy(&min_data_key_dbt);
		return ret;
	}

	//print_key(__func__, min_data_key_dbt.data, min_data_key_dbt.size);
	//pr_info("last block num: %d, current block_num: %d\n", last_block_num, current_block_num);
	total_block_num = last_block_num - current_block_num + 1;

	//ret = data_db->del_multi(data_db, txn,
	//                         &min_data_key_dbt,
	//                         &max_data_key_dbt,
	//                         0, LIGHTFS_DATA_DEL_MULTI);
#ifdef PINK
	while (total_block_num) {
		//TXN_GOTO_LABEL(retry);
		//if (new_txn) {
		//	ftfs_bstore_txn_begin(sbi->db_dev, NULL, &txn, TXN_MAY_WRITE);
		//}
		transfering_block_cnt = total_block_num > LIGHTFS_TXN_LIMIT ? LIGHTFS_TXN_LIMIT : total_block_num;
		ret = data_db->del_multi(data_db, txn, &min_data_key_dbt, transfering_block_cnt, 0, LIGHTFS_DATA_DEL_MULTI);
		//if (ret) {
		//	DBOP_JUMP_ON_CONFLICT(ret, retry);
		//	ftfs_bstore_txn_abort(txn);
		//} else {
		//	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		//	COMMIT_JUMP_ON_CONFLICT(ret, retry);
		//}
		current_block_num += transfering_block_cnt;
		total_block_num -= transfering_block_cnt;
		copy_data_dbt_from_inode(&min_data_key_dbt, inode, current_block_num);
	}
#else
	do {
		//ftfs_error(__func__, "cur :%d, last: %d\n", current_block_num, last_block_num);
		ret = data_db->del(data_db, txn, &max_data_key_dbt, LIGHTFS_DATA_DEL);
		if (ret) {
			ftfs_error(__func__, "왜...\n");
		} else {
			current_block_num++;
			copy_data_dbt_from_inode(&max_data_key_dbt, inode, current_block_num);
		}

	} while (last_block_num >= current_block_num);
#endif

	//ftfs_error(__func__, "안들어가냐??...%d %d\n", ret, offset);
	if (!ret && offset) {
		//TXN_GOTO_LABEL(update_retry);
		//ftfs_bstore_txn_begin(sbi->db_dev, NULL, &txn, TXN_MAY_WRITE);
		//ftfs_error(__func__, "안들어가냐??...\n");
		dbt_setup(&value, NULL, 0);
		ftfs_data_key_set_blocknum(((char *)min_data_key_dbt.data),
		                           min_data_key_dbt.size, new_num);
		ret = data_db->update(data_db, txn, &min_data_key_dbt,
		                      &value, offset, LIGHTFS_DATA_UPDATE);
		//if (ret) {
		//	DBOP_JUMP_ON_CONFLICT(ret, update_retry);
		//	ftfs_bstore_txn_abort(txn);
		//} else {
		//	ret = ftfs_bstore_txn_commit(txn, DB_TXN_NOSYNC);
		//	COMMIT_JUMP_ON_CONFLICT(ret, update_retry);
		//}
	}

	dbt_destroy(&max_data_key_dbt);
	dbt_destroy(&min_data_key_dbt);

	return ret;
}

int ftfs_bstore_scan_one_page(DB *data_db, DBT *meta_dbt, DB_TXN *txn, struct page *page, struct inode *inode)
{
	int ret;
	DBT data_dbt;
	char *buf;

	//// now data_db keys start from 1
	// KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt, PAGE_TO_BLOCK_NUM(page));
	uint64_t page_block_num = PAGE_TO_BLOCK_NUM(page);
	loff_t size = i_size_read(inode);
	uint64_t last_block_num = ftfs_get_block_num_by_size(size);

	if (page_block_num > last_block_num) {
		//ftfs_error(__func__, "block num: %d, size: %d\n", page_block_num, size);
		buf = kmap_atomic(page);
		memset(buf, 0, FTFS_BSTORE_BLOCKSIZE);
		kunmap_atomic(buf);
		return 0;
	}
	ret = alloc_data_dbt_from_inode(&data_dbt, inode, page_block_num);
	if (ret)
		return ret;

	buf = kmap_atomic(page);
	ret = ftfs_bstore_get(data_db, &data_dbt, txn, buf, inode);
	if (ret == -ENOENT) {
		memset(buf, 0, FTFS_BSTORE_BLOCKSIZE);
		ret = 0;
	}
	kunmap_atomic(buf);

	dbt_destroy(&data_dbt);

	return ret;
}

struct ftfs_scan_pages_cb_info {
	char *meta_key;
	struct ftio *ftio;
	int do_continue;
	//uint64_t ino;
	struct inode *inode;
	uint64_t block_cnt;
};

static int ftfs_scan_pages_cb(DBT const *key, DBT const *val, void *extra)
{
	char *data_key = key->data;
	struct ftfs_scan_pages_cb_info *info = extra;
	struct ftio *ftio = info->ftio;
	size_t block_off;
	uint64_t block_num;
	loff_t size;

	if (key_is_same_of_ino(data_key, info->inode->i_ino)) {
		struct page *page = ftio_current_page(ftio);
		uint64_t page_block_num = PAGE_TO_BLOCK_NUM(page);
		char *page_buf;

		//print_key(__func__, key->data, key->size);
		//ftfs_error(__func__, "page_block_num: %d, info->block_cnt: %d\n", page_block_num, info->block_cnt);

		while (page_block_num < ftfs_data_key_get_blocknum(data_key, key->size)) {
			page_buf = kmap_atomic(page);
			if (!page_buf) {
				pr_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1\n");
			}
			memset(page_buf, 0, PAGE_SIZE);
			kunmap_atomic(page_buf);

			ftio_advance_page(ftio);
			if (ftio_job_done(ftio))
				break;
			page = ftio_current_page(ftio);
			page_block_num = PAGE_TO_BLOCK_NUM(page);
			info->block_cnt--;
		}

		if (page_block_num == ftfs_data_key_get_blocknum(data_key, key->size)) {
			size = i_size_read(info->inode);
			block_off = block_get_off_by_position(size);
			block_num = ftfs_get_block_num_by_size(size);
			page_buf = kmap_atomic(page);
			if (!page_buf || !val->data) {
				pr_info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!2\n");
			}
			if (val->size)
				memcpy(page_buf, val->data, val->size);
			if (page_block_num == block_num && block_off && block_off < PAGE_SIZE) {
				memset(page_buf + block_off, 0, PAGE_SIZE - block_off);
			}
			//if (val->size < PAGE_SIZE)
			//	memset(page_buf + val->size, 0,
			//	       PAGE_SIZE - val->size);

			kunmap_atomic(page_buf);
			ftio_advance_page(ftio);
			info->block_cnt--;
		}

		info->do_continue = !ftio_job_done(ftio);
	} else
		info->do_continue = 0;

	return 0;
}

static inline void ftfs_bstore_fill_rest_page(struct ftio *ftio)
{
	struct page *page;
	char *page_buf;

	while (!ftio_job_done(ftio)) {
		page = ftio_current_page(ftio);
		page_buf = kmap_atomic(page);
		memset(page_buf, 0, PAGE_SIZE);
		kunmap_atomic(page_buf);
		ftio_advance_page(ftio);
	}
}

int ftfs_bstore_scan_pages(DB *data_db, DBT *meta_dbt, DB_TXN *txn, struct ftio *ftio, struct inode *inode)
{
	int ret, r = 0;
	struct ftfs_scan_pages_cb_info info;
	DBT data_dbt;
	DBC *cursor;
	loff_t size = i_size_read(inode);
	uint64_t current_block_num, block_cnt, tmp, last_block_num;
	char *buf;
	struct page *page;
	int i;


	//ftfs_error(__func__, "meta key path =%s\n", meta_key->path);
	if (ftio_job_done(ftio))
		return 0;

	page = ftio_current_page(ftio);
	current_block_num = PAGE_TO_BLOCK_NUM(page);
	last_block_num = PAGE_TO_BLOCK_NUM(ftio_last_page(ftio));
	block_cnt = ftfs_get_block_num_by_size(size) - current_block_num + 1;
	//ftfs_error(__func__, "1: ftio->ft_bvidx: %d, ftio->ft_vcnt: %d block_cnt: %d, size: %d, current_block_num: %d\n", ftio->ft_bvidx, ftio->ft_vcnt, block_cnt, size, current_block_num);
	block_cnt = block_cnt > last_block_num - current_block_num + 1 ? last_block_num - current_block_num + 1: block_cnt; 
	//ftfs_error(__func__, "2: ftio->ft_bvidx: %d, ftio->ft_vcnt: %d block_cnt: %d, size: %d, current_block_num: %d\n", ftio->ft_bvidx, ftio->ft_vcnt, block_cnt, size, current_block_num);
	/*
	if (block_cnt > 1) {
		for (i = 0; i < block_cnt; i++) {
			tmp = PAGE_TO_BLOCK_NUM(ftio_page_at(ftio, i));
			ftfs_error(__func__, "FUCK!!! block_cnt: %d, current_block: %d, tmp: %d\n", block_cnt, current_block_num, tmp);
		}
	}
	*/
	
	if (block_cnt == 0) {
		WARN_ON(1);
		ftfs_bstore_fill_rest_page(ftio);
	}
	
	//KOO:key
	//ret = alloc_data_dbt_from_meta_dbt(&data_dbt, meta_dbt,
	ret = alloc_data_dbt_from_inode(&data_dbt, inode,
			current_block_num);
	if (ret)
		return ret;

#ifdef GET_MULTI
	info.meta_key = meta_dbt->data;
	info.ftio = ftio;
	info.inode = inode;
	info.block_cnt = block_cnt;

	while (info.do_continue && !r)
		r = data_db->get_multi(data_db, txn, &data_dbt, block_cnt, ftfs_scan_pages_cb, &info, LIGHTFS_GET_MULTI);
	if (r && r != DB_NOTFOUND)
		ret = r;
	if (!ret)
		ftfs_bstore_fill_rest_page(ftio);

	BUG_ON(r);
#else
	if (block_cnt < 5) {
		while(block_cnt--) {
			buf = kmap_atomic(page);
			ret = ftfs_bstore_get(data_db, &data_dbt, txn, buf, inode);
			if (ret == -ENOENT) {
				memset(buf, 0, FTFS_BSTORE_BLOCKSIZE);
				ret = 0;
			}
			kunmap_atomic(buf);
			if (!(ftio_current_page(ftio) == ftio_last_page(ftio))) {
				//ftfs_error(__func__, "한개만 보낸다.\n");
				ftio_advance_page(ftio);
				ftfs_bstore_fill_rest_page(ftio);
			} else {
				ftio_advance_page(ftio);
			}
		}
	} else {
		ret = data_db->cursor(data_db, txn, &cursor, LIGHTFS_DATA_CURSOR);
		if (ret)
			goto free_out;

		info.meta_key = meta_dbt->data;
		info.ftio = ftio;
		info.inode = inode;
		info.block_cnt = block_cnt;

		r = cursor->c_getf_set_range(cursor, info.block_cnt, &data_dbt, ftfs_scan_pages_cb, &info);
		while (info.do_continue && !r)
			r = cursor->c_getf_next(cursor, info.block_cnt, ftfs_scan_pages_cb, &info);
		if (r && r != DB_NOTFOUND)
			ret = r;
		if (!ret)
			ftfs_bstore_fill_rest_page(ftio);
	
		r = cursor->c_close(cursor);
		BUG_ON(r);
	}
#endif


free_out:
	dbt_destroy(&data_dbt);

	return ret;
}

#ifdef READA
int ftfs_bstore_reada_pages(DB *data_db, DBT *meta_dbt, DB_TXN *txn, struct ftio *ftio, struct inode *inode, unsigned iter)
{
	int ret, r = 0;
	DBT data_dbt;
	loff_t size = i_size_read(inode);
	uint64_t current_block_num, block_cnt;
	char *buf;
	struct reada_entry *last_ra_entry, *ra_entry;
	struct ftfs_inode *ftfs_inode = FTFS_I(inode);
	struct page *page;

	if (ftfs_inode->ra_entry) {
		last_ra_entry = list_last_entry(&ftfs_inode->ra_list, struct reada_entry, list);
		current_block_num = last_ra_entry->reada_block_start + last_ra_entry->reada_block_len;
	} else {
		page = ftio_last_page(ftio);
		current_block_num = (PAGE_TO_BLOCK_NUM(page) * iter) + 1;
	}
	block_cnt = ftfs_get_block_num_by_size(size) + 1 - current_block_num;
	ftfs_error(__func__, "1: ftio->ft_bvidx: %d, ftio->ft_vcnt: %d,start_block: %ld, block_cnt: %ld\n", ftio->ft_bvidx, ftio->ft_vcnt, current_block_num, block_cnt);
	block_cnt = block_cnt > ftio->ft_vcnt * READA_MULTIPLIER ? ftio->ft_vcnt * READA_MULTIPLIER : block_cnt; 
	ftfs_error(__func__, "2: ftio->ft_bvidx: %d, ftio->ft_vcnt: %d,start_block: %ld, block_cnt: %ld\n", ftio->ft_bvidx, ftio->ft_vcnt, current_block_num, block_cnt);

	if (block_cnt == 0) {
		return EEOF;
	}
	
	ret = alloc_data_dbt_from_inode(&data_dbt, inode,
			current_block_num);
	if (ret)
		return ret;
	/*
	if (ra_entry) {
		ra_entry = lightfs_reada_reuse(inode, current_block_num, block_cnt);

	} else {
		ra_entry = lightfs_reada_alloc(inode, current_block_num, block_cnt);
	}
	FTFS_I(inode)->ra_entry = ra_entry;
	*/
	ra_entry = lightfs_reada_alloc(inode, current_block_num, block_cnt);

	r = data_db->get_multi_reada(data_db, txn, &data_dbt, block_cnt, ra_entry, LIGHTFS_GET_MULTI_READA);

	dbt_destroy(&data_dbt);

	return ret;
}
#endif

struct ftfs_die_cb_info {
	char *meta_key;
	int *is_empty;
	ino_t ino;
	uint64_t block_cnt;
};

static int ftfs_die_cb(DBT const *key, DBT const *val, void *extra)
{
	struct ftfs_die_cb_info *info = extra;
	char *current_meta_key = key->data;

	//*(info->is_empty) = !meta_key_is_child_of_meta_key(current_meta_key, info->meta_key);
	*(info->is_empty) = !meta_key_is_child_of_ino(current_meta_key, info->ino);

	return 0;
}

int ftfs_dir_is_empty(DB *meta_db, DBT *meta_dbt, DB_TXN *txn, int *is_empty, struct inode *inode)
{
	int ret, r;
	struct ftfs_die_cb_info info;
	DBT start_meta_dbt;
	DBC *cursor;

	return 1;

	//KOO:key
	//ret = alloc_child_meta_dbt_from_meta_dbt(&start_meta_dbt, meta_dbt, "");
	ret = alloc_child_meta_dbt_from_inode(&start_meta_dbt, inode, "");
	if (ret)
		return ret;

	ret = meta_db->cursor(meta_db, txn, &cursor, LIGHTFS_META_CURSOR);
	if (ret)
		goto out;

	info.meta_key = meta_dbt->data;
	info.is_empty = is_empty;
	info.ino = inode->i_ino;
	info.block_cnt = 1;
	ret = cursor->c_getf_set_range(cursor, info.block_cnt, &start_meta_dbt, ftfs_die_cb, &info);
	if (ret == DB_NOTFOUND) {
		ret = 0;
		*is_empty = 1;
	}

	r = cursor->c_close(cursor);
	BUG_ON(r);
out:
	dbt_destroy(&start_meta_dbt);

	return ret;
}

static int
ftfs_bstore_move_copy(DB *meta_db, DB *data_db, DBT *old_meta_dbt,
		      DBT *new_meta_dbt, DB_TXN *txn,
                      enum ftfs_bstore_move_type type)
{
	int r, ret, rot;
	char *it_key[2], *new_key, *block_buf;
	DBT val_dbt, key_dbt[2], new_key_dbt, new_prefix_dbt, old_prefix_dbt;
	struct ftfs_metadata meta;
	DBC *cursor;

	ret = -ENOMEM;
	it_key[0] = it_key[1] = new_key = block_buf = NULL;
	dbt_init(&old_prefix_dbt);
	dbt_init(&new_prefix_dbt);
	if ((it_key[0] = kmalloc(KEY_MAX_LEN, GFP_NOIO)) == NULL)
		goto out;
	if ((it_key[1] = kmalloc(KEY_MAX_LEN, GFP_NOIO)) == NULL)
		goto free_out;
	if ((new_key = kmalloc(KEY_MAX_LEN, GFP_NOIO)) == NULL)
		goto free_out;
	if ((block_buf = kmalloc(FTFS_BSTORE_BLOCKSIZE, GFP_NOIO)) == NULL)
		goto free_out;

	dbt_setup_buf(&key_dbt[0], it_key[0], KEY_MAX_LEN);
	dbt_setup_buf(&key_dbt[1], it_key[1], KEY_MAX_LEN);
	dbt_setup_buf(&new_key_dbt, new_key, KEY_MAX_LEN);
	if (type == FTFS_BSTORE_MOVE_DIR) {
		ret = alloc_meta_dbt_prefix(&old_prefix_dbt, old_meta_dbt);
		if (ret)
			goto free_out;
		ret = alloc_meta_dbt_prefix(&new_prefix_dbt, new_meta_dbt);
		if (ret)
			goto free_out;

		dbt_setup_buf(&val_dbt, &meta, sizeof(meta));
		rot = 0;
		copy_child_meta_dbt_from_meta_dbt(&key_dbt[rot], old_meta_dbt, "");

		ret = meta_db->cursor(meta_db, txn, &cursor, LIGHTFS_META_CURSOR);
		if (ret)
			goto free_out;
		r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt, DB_SET_RANGE);
		while (!r) {
			// is this key in the subtree ?
			if (!key_is_in_subtree_of_prefix(it_key[rot],
				old_prefix_dbt.data, old_prefix_dbt.size))
				break;

			copy_meta_dbt_movdir(&old_prefix_dbt, &new_prefix_dbt,
			                     &key_dbt[rot], &new_key_dbt);
			ret = meta_db->put(meta_db, txn, &new_key_dbt, &val_dbt,
			                   LIGHTFS_DATA_SET);
			if (ret) {
freak_out:
				cursor->c_close(cursor);
				goto free_out;
			}
			rot = 1 - rot;
			r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt,
			                  DB_NEXT);
			ret = meta_db->del(meta_db, txn, &key_dbt[1 - rot],
			                   LIGHTFS_META_DEL);
			if (ret)
				goto freak_out;
		}

		if (r && r != DB_NOTFOUND) {
			ret = r;
			goto freak_out;
		}

		cursor->c_close(cursor);

		dbt_setup_buf(&val_dbt, block_buf, FTFS_BSTORE_BLOCKSIZE);
		rot = 0;
		copy_child_data_dbt_from_meta_dbt(&key_dbt[rot], old_meta_dbt, "", 0);
		ret = data_db->cursor(data_db, txn, &cursor, LIGHTFS_DATA_CURSOR);
		if (ret)
			goto free_out;
		r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt, DB_SET_RANGE);
		while (!r) {
			if (!key_is_in_subtree_of_prefix(it_key[rot],
				old_prefix_dbt.data, old_prefix_dbt.size))
				break;

			copy_data_dbt_movdir(&old_prefix_dbt, &new_prefix_dbt,
			                     &key_dbt[rot], &new_key_dbt);
			ret = data_db->put(data_db, txn, &new_key_dbt, &val_dbt,
			                   LIGHTFS_DATA_SET);
			if (ret)
				goto freak_out;
			rot = 1 - rot;
			r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt,
			                  DB_NEXT);
			ret = data_db->del(data_db, txn, &key_dbt[1 - rot],
			                   LIGHTFS_DATA_DEL);
			if (ret)
				goto freak_out;
		}
	} else {
		// only need to move data if we are renaming a file
		char *old_meta_key = old_meta_dbt->data;

		dbt_setup_buf(&val_dbt, block_buf, FTFS_BSTORE_BLOCKSIZE);
		rot = 0;

		copy_data_dbt_from_meta_dbt(&key_dbt[rot], old_meta_dbt, 0);
		ret = data_db->cursor(data_db, txn, &cursor, LIGHTFS_DATA_CURSOR);
		if (ret)
			goto free_out;
		r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt, DB_SET_RANGE);
		while (!r) {
			if (!key_is_same_of_key(it_key[rot], old_meta_key))
				break;

			copy_data_dbt_movdir(old_meta_dbt, new_meta_dbt,
			                     &key_dbt[rot], &new_key_dbt);
			ret = data_db->put(data_db, txn, &new_key_dbt, &val_dbt,
			                   LIGHTFS_DATA_SET);
			if (ret)
				goto freak_out;

			rot = 1 - rot;
			r = cursor->c_get(cursor, &key_dbt[rot], &val_dbt,
			                  DB_NEXT);
			ret = data_db->del(data_db, txn, &key_dbt[1 - rot],
			                   LIGHTFS_DATA_DEL);
			if (ret)
				goto freak_out;
		}

		if (r && r != DB_NOTFOUND) {
			ret = r;
			goto freak_out;
		}

		cursor->c_close(cursor);
	}

free_out:
	dbt_destroy(&new_prefix_dbt);
	dbt_destroy(&old_prefix_dbt);
	if (block_buf)
		kfree(block_buf);
	if (new_key)
		kfree(new_key);
	if (it_key[1])
		kfree(it_key[1]);
	if (it_key[0])
		kfree(it_key[0]);
out:
	return ret;
}

int
ftfs_bstore_move(DB *meta_db, DB *data_db, DBT *old_meta_dbt, DBT *new_meta_dbt,
                 DB_TXN *txn, enum ftfs_bstore_move_type type)
{
	return ftfs_bstore_move_copy(meta_db, data_db, old_meta_dbt,
	                             new_meta_dbt, txn, type);
}

/*
 * XXX: delete following functions
 */
int bstore_checkpoint(void)
{
	if (unlikely(!XXX_db_env))
		return -EINVAL;
	return XXX_db_env->txn_checkpoint(XXX_db_env, 0, 0, 0);
}

int bstore_hot_flush_all(void)
{
	int ret;
	uint64_t loops = 0;

	if (!XXX_data_db)
		return -EINVAL;

	ret = XXX_data_db->hot_optimize(XXX_data_db, NULL, NULL, NULL, NULL, &loops);

	ftfs_log(__func__, "%llu loops, returning %d", loops, ret);

	return ret;
}

int ftfs_bstore_dump_node(bool is_data, int64_t b) {

	int ret;
	DB * db;
	if (!XXX_data_db || !XXX_meta_db)
			return -EINVAL;

	db = is_data? XXX_data_db:XXX_meta_db;
	ret = db->dump_ftnode(db, b);
	ftfs_log(__func__, "returning %d", ret);

	return ret;
}
void ftfs_print_engine_status(void)
{
	uint64_t nrows;
	int buff_size;
	char *buff;

	if (!XXX_db_env) {
		ftfs_error(__func__, "no db_env");
		return;
	}

	XXX_db_env->get_engine_status_num_rows(XXX_db_env, &nrows);
	buff_size = nrows * 128; //assume 128 chars per row
	buff = (char *)kmalloc(sizeof(char) * buff_size, GFP_NOIO);
	if (buff == NULL)
		return;

	XXX_db_env->get_engine_status_text(XXX_db_env, buff, buff_size);
	kfree(buff);
}
