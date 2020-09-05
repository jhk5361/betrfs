#ifndef __LIGHTFS_IO_H__
#define __LIGHTFS_IO_H__

#include "lightfs.h"

#define LIGHTFS_IO_LARGE_BUF (2 * 1024 * 1024 + 200 * 1024)
#define LIGHTFS_IO_SMALL_BUF (8 * 1024)

int lightfs_io_create (DB_IO **db_io);

static inline int lightfs_io_set_txn_id(char *buf, uint32_t txn_id, int idx)
{
	*((uint32_t *)buf) = txn_id;
	return idx + sizeof(uint32_t);
}

static inline int lightfs_io_set_type(char *buf, uint8_t type, int idx)
{
	*buf = type;
	return idx + sizeof(uint8_t);
}

static inline int lightfs_io_set_key_len(char *buf, uint16_t key_len, int idx)
{
	*((uint16_t *)buf) = key_len;
	return idx + sizeof(uint16_t);
}

static inline int lightfs_io_set_key(char *buf, uint16_t key_len, char *key, int idx)
{
	memcpy(buf, key, key_len);
	return idx + key_len;
}

static inline int lightfs_io_set_off(char *buf, uint16_t off, int idx)
{
	*((uint16_t *)buf) = off;
	return idx + sizeof(uint16_t);
}

static inline int lightfs_io_set_value_len(char *buf, uint16_t value_len, int idx)
{
	*((uint16_t *)buf) = value_len;
	return idx + sizeof(uint16_t);
}

static inline int lightfs_io_set_value(char *buf, uint16_t value_len, char *value, int idx)
{
	memcpy(buf, value, value_len);
	return idx + value_len;
}

static inline int lightfs_io_set_buf_ptr(char *buf, char *buf_ptr, int idx)
{
	*((char **)buf) = buf_ptr;
	return idx + sizeof(char *);
}

// should set txn_id before calling this function
// SET: all
// UPDATE: all
// DEL: type, key_len, key
// DEL_MULTI: type, key_len, key, off (count of deleted key)
static inline int lightfs_io_set_buf_set(char *buf, uint8_t type, uint16_t key_len, char *key, uint16_t off, uint16_t value_len, char *value, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	idx = lightfs_io_set_off(buf, off, idx);
	idx = lightfs_io_set_value_len(buf, value_len, idx);
	idx = lightfs_io_set_value(buf, value_len, value, idx);
	return idx;
}

static inline int lightfs_io_set_buf_update(char *buf, uint8_t type, uint16_t key_len, char *key, uint16_t off, uint16_t value_len, char *value, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	idx = lightfs_io_set_off(buf, off, idx);
	idx = lightfs_io_set_value_len(buf, value_len, idx);
	idx = lightfs_io_set_value(buf, 4096, value, idx);
	return idx;
}


static inline int lightfs_io_set_buf_del(char *buf, uint8_t type, uint16_t key_len, char *key, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	return idx;
}

static inline int lightfs_io_set_buf_del_multi(char *buf, uint8_t type, uint16_t key_len, char *key, uint16_t off, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	idx = lightfs_io_set_off(buf, off, idx);
	return idx;
}

static inline int lightfs_io_set_buf_get(char *buf, uint8_t type, uint16_t key_len, char *key, uint16_t value_len, char *buf_ptr, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	idx = lightfs_io_set_value_len(buf, value_len, idx);
	idx = lightfs_io_set_buf_ptr(buf, buf_ptr, idx);
	return idx;
}

static inline int lightfs_io_set_buf_iter(char *buf, uint8_t type, uint16_t key_len, char *key, uint16_t off, uint16_t value_len, char *buf_ptr, int idx)
{
	idx = lightfs_io_set_type(buf, type, idx);
	idx = lightfs_io_set_key_len(buf, key_len, idx);
	idx = lightfs_io_set_key(buf, key_len, key, idx);
	idx = lightfs_io_set_off(buf, off, idx);
	idx = lightfs_io_set_value_len(buf, value_len, idx);
	idx = lightfs_io_set_buf_ptr(buf, buf_ptr, idx);
	return idx;
}




#endif
