/* -*- mode: C++; c-basic-offset: 8; indent-tabs-mode: t -*- */
// vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab:
#ifndef _FTFS_H
#define _FTFS_H

#  define FTFS_DEBUG_ON(err)

#include "ftfs_fs.h"

static inline void ftfs_error (const char * function, const char * fmt, ...)
{
#ifdef FTFS_DEBUG
	va_list args;

	va_start(args, fmt);
	printk(KERN_CRIT "ftfs error: %s: ", function);
	vprintk(fmt, args);
	printk(KERN_CRIT "\n");
	va_end(args);
#endif
}

//samething as ftfs_error...when ftfs fs calls needs to dump info out
static inline void ftfs_log(const char * function, const char * fmt, ...)
{
#ifdef FTFS_DEBUG
	va_list args;
	va_start(args, fmt);
	printk(KERN_ALERT "ftfs log: %s: ", function);
	vprintk(fmt, args);
	printk(KERN_ALERT "\n");
	va_end(args);
#endif
}




#endif
