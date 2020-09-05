ifdef M
	include $(M)/.mkinclude
else
	include $(PWD)/.mkinclude
endif

obj-m += ftfs.o


KBUILD_CFLAGS += -DFTFS_DEBUG #-DSOUTHBOUND_DEBUG #-DFTFS_MEM_DEBUG # -DFTFS_DEBUG_PTRS
#ftfs-y := ftfs_super.o ftfs_bstore.o ftfs_metadata.o rbtreekv.o ftfs_module.o
ftfs-y := ftfs_super.o ftfs_bstore.o rbtreekv.o ftfs_module.o

all:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) clean
