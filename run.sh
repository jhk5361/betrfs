USER=koo
REPO=/home/$USER/src/betrfs
MODDIR=filesystem
MODULE=ftfs.ko
MOUNTPOINT=/mnt/betrfs
SBDISK=/dev/nvme2n1

sudo mkfs.ext4 $SBDISK
mkdir -p $MOUNTPOINT
mount -t ext4 $SBDISK $MOUNTPOINT
cd $MOUNTPOINT;
rm -rf *;
mkdir db;
mkdir dev;
touch dev/null;
mkdir tmp;
chmod 1777 tmp;
cd -;
umount $MOUNTPOINT

cd $REPO/$MODDIR; make; cd -;
#sudo modprobe zlib
sudo insmod /lib/modules/4.15.18+/kernel/crypto/zlib.ko
sudo insmod $REPO/$MODDIR/$MODULE sb_dev=$SBDISK sb_fstype=ext4

touch dummy.dev
sudo losetup /dev/loop4 dummy.dev
sudo mount -t ftfs /dev/loop4 $MOUNTPOINT
