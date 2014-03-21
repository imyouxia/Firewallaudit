#!/bin/bash
gcc -g -lpthread -lzlog -lhiredis -lssh2 -L/usr/local/lib -lmysqlclient -lm *.c -o fw_node
