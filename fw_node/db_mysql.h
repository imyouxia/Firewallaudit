#ifndef __INCLUDE_DB_MYSQL_H
#define __INCLUDE_DB_MYSQL_H

#include <mysql/mysql.h>

#define RD_DB 1
#define RW_DB 2

typedef struct mysql_server_info {
	char * 					server_addr;
	unsigned short	server_port;
	char * 					user;
	char *					password;
	char *					database;
	int							flag;
	MYSQL 					conn;
} mysql_server_info;

int load_mysql_conf(const char * buff);
int ops_mysql_exec_modify(const char * sql);
#endif
