#!/bin/bash
unzip hiredis-master.zip
cd hiredis-master && make && make install
cd ..
rm -rf hiredis-master

tar -zvxf openssl-1.0.1e.tar.gz
cd openssl-1.0.1e
./config -fPIC --prefix=/usr/local/openssl && make && make install
cd ..
rm -rf openssl-1.0.1e

tar -zvxf libssh2-1.4.3.tar.gz
cd libssh2-1.4.3
./configure --with-libssl-prefix=/usr/local/openssl CPPFLAGS="-I/usr/local/openssl/include" LDFLAGS="-ldl -L/usr/local/openssl/lib" && make && make install
cd ..
rm -rf libssh2-1.4.3

tar -zxvf redis-2.6.12.tar.gz
cd redis-2.6.12
make && make install
cd ..
rm -rf redis-2.6.12
mkdir -p /etc/redis/ && cp redis.conf /etc/redis/
redis-server /etc/redis/redis.conf

tar zxvf zlog-latest-stable-53958428.tar.gz
cd zlog-latest-stable-53958428
make && make install
cd ..
rm -rf zlog-latest-stable-53958428

tar zvxf mysql-connector-c-6.1.0-linux-glibc2.5-i686.tar.gz
cd mysql-connector-c-6.1.0-linux-glibc2.5-i686.tar.gz
cp -r lib/* /usr/local/lib
mkdir /usr/local/include/mysql
cp -r include/* /usr/local/include/mysql/
cd ..
rm -rf mysql-connector-c-6.1.0-linux-glibc2.5-i686.tar.gz

mkdir -p /home/fw_audit/log
mkdir -p /home/fw_audit/bin
mkdir -p /home/fw_audit/fw_cfg
chmod -R 777 /home/fw_audit/
cp -r fw_audit /home/fw_audit/bin/

echo '/usr/local/lib' >> /etc/ld.so.conf
ldconfig -v
