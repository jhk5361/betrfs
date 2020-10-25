ifdef M
	include $(M)/.mkinclude
else
	include $(PWD)/.mkinclude
endif

obj-m += ftfs.o


KBUILD_CFLAGS +=  -I./cheeze \
				  -DLIGHTFS \
				  -DRB_LOCK \
				  -DPINK \
				  -DSUPER_NOLOCK \
				  -DMONITOR \
				  -DGET_MULTI \
				  -DWB \
				  -DIS_IN_VM \
				  -DPRINT_QD \
#				  -DFTFS_DEBUG \
#				  -DCALL_TRACE \
#				  -DTIME_CHECK \
#				  -DTXN_BUFFER \
#				  -DTXN_TIME_CHECK \
#				  -DBETR \
#				  -DCALL_TRACE_TIME \
#				  -DRB_LOCK \
#				  -DRB_CACHE \
#				  -DCHEEZE \
#				  -DEMULATION \
#				  -DLIGHTFS_UPSERT \

#KBUILD_CFLAGS +=  -DLIGHTFS -DEMULATION -DRB_LOCK #-DFTFS_DEBUG #-DSOUTHBOUND_DEBUG #-DFTFS_MEM_DEBUG # -DFTFS_DEBUG_PTRS
#ftfs-y := ftfs_super.o ftfs_bstore.o ftfs_metadata.o rbtreekv.o ftfs_module.o
ftfs-y := lightfs_super.o \
		  lightfs_bstore.o \
		  lightfs_txn_hdlr.o \
		  lightfs_io.o \
		  lightfs_db.o \
		  lightfs_db_env.o \
		  lightfs_cache.o \
		  bloomfilter.o \
		  lightfs_queue.o \
		  murmur3.o \
		  rbtreekv.o \
		  ./cheeze/queue.o \
		  ./cheeze/blk.o \
		  ./cheeze/shm.o \
		  ftfs_module.o \
#./cheeze/chr.o \


all:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) clean
