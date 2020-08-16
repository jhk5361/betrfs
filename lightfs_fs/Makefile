ifdef M
	include $(M)/.mkinclude
else
	include $(PWD)/.mkinclude
endif

obj-m += ftfs.o


KBUILD_CFLAGS += -DFTFS_DEBUG -DLIGHTFS -DEMULATION #-DSOUTHBOUND_DEBUG #-DFTFS_MEM_DEBUG # -DFTFS_DEBUG_PTRS
#ftfs-y := ftfs_super.o ftfs_bstore.o ftfs_metadata.o rbtreekv.o ftfs_module.o
ftfs-y := lightfs_super.o lightfs_bstore.o lightfs_txn_hdlr.o lightfs_io.o lightfs_db.o lightfs_db_env.o bloomfilter.o murmur3.o rbtreekv.o ftfs_module.o

all:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) clean
