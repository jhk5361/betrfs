#ifndef __LIGHTFS_DB_ENV_H__
#define __LIGHTFS_DB_ENV_H__

#include "ftfs_fs.h"

int lightfs_db_evn_create(DB_ENV **envp, uint32_t flags);

#endif
