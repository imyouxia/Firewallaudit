#!/bin/bash
gcc -g -lpthread -L/usr/local/lib -lzlog -lhiredis -L/usr/local/lib -lssh2 -L/usr/lib64/mysql -lmysqlclient -lm *.c -o fw_audit
