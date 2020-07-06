umount /mnt/betrfs
rmmod filesystem/ftfs.ko
losetup -d /dev/loop4
