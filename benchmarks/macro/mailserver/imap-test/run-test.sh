sudo dovecot stop
cd ~/ft-index/benchmarks/
sudo ./cleanup-fs.sh
sudo ./setup-ftfs.sh
cd -
sudo cp -r /home/ftfstest/ftfstest/ /mnt/benchmark/
sudo chown -R ftfstest:ftfstest /mnt/benchmark/ftfstest/
sudo dovecot
./imap-punish.py
