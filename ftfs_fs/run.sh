touch dummy.dev
sudo losetup /dev/loop3 dummy.dev
sudo mount -t ftfs /dev/loop3 $1
