#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <mysql/mysql.h>

#include "constant.h"
#include "db_mysql.h"
#include "zlog.h"

#define SQL_LENGTH	1024
static mysql_server_info g_server;

extern zlog_category_t * logger;

static int __mysql_connect(void)
{
	//连接到数据库
	if (!mysql_real_connect(&g_server.conn, g_server.server_addr,
			g_server.user, g_server.password, g_server.database, g_server.server_port, NULL, 0)) {
		zlog_fatal(logger, "connect mysql failed: %s", mysql_error(&g_server.conn));
		return FAIL;
	}

	char value = 1;
	mysql_options(&g_server.conn, MYSQL_OPT_RECONNECT, (char*)&value);
	return OK;
}


int load_mysql_conf(const char * buff)
{
	int retv;
	retv = read_profile_string("mysql", "server", &g_server.server_addr, "localhost", buff);
	if (retv == FAIL) {
		zlog_error(logger, "mysql server addr fetch failed");
		return FAIL;
	}
	zlog_debug(logger, "mysql server addr: %s", g_server.server_addr);

	g_server.server_port = read_profile_int("mysql", "port", 3306, buff);
	if (g_server.server_port == FAIL) {
		zlog_error(logger, "mysql server port fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "mysql server port: %d", g_server.server_port);

	retv = read_profile_string("mysql", "user", &g_server.user, "root", buff);
	if (retv == FAIL) {
		zlog_error(logger, "mysql user fetch failed");
		return FAIL;
	}
	zlog_debug(logger, "mysql user: %s", g_server.user);

	retv = read_profile_string("mysql", "password", &g_server.password, "123456", buff);
	if (retv == FAIL) {
		zlog_error(logger, "mysql password fetch failed");
		return FAIL;
	}
	zlog_debug(logger, "mysql password: %s", g_server.password);

	retv = read_profile_string("mysql", "database", &g_server.database, "fw_audit", buff);
	if (retv == FAIL) {
		zlog_error(logger, "mysql database fetch failed");
		return FAIL;
	}
	zlog_debug(logger, "mysql database: %s", g_server.database);

	g_server.flag = read_profile_int("mysql", "flag", 0, buff);
	if (g_server.flag == FAIL) {
		zlog_error(logger, "mysql server flag fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "mysql server flag: %d", g_server.flag);

	mysql_init(&g_server.conn);
	if (__mysql_connect() == FAIL)
		return FAIL;

	return OK;
}

static void mysql_disconnect(void)
{
	mysql_close(&g_server.conn);
}

static int __ops_mysql_exec_modify(const char *sql)
{
	int sign = 0;
	if (NULL == sql ) return FAIL;

	if (mysql_query(&g_server.conn, sql)) {
		sign = 1;
		zlog_error(logger, "execute sql '%s' failed: %s", sql, mysql_error(&g_server.conn));
		mysql_close(&g_server.conn);
		if (__mysql_connect() == FAIL)
			return FAIL;
	}

	if (sign == 1) {
		if (mysql_query(&g_server.conn, sql))
			zlog_debug(logger, "execute sql '%s' successfully: %s", sql, mysql_error(&g_server.conn));
	} else if (sign == 0) {
		zlog_debug(logger, "execute sql '%s' successfully: %s", sql, mysql_error(&g_server.conn));
	}

	return OK;	
}

int ops_mysql_exec_modify(const char * sql)
{
	 __ops_mysql_exec_modify(sql);
	mysql_disconnect();
	return OK;
}



#if 0
static int ops_mysql_exec_query(void **result, unsigned int n, const char * sql)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	int ix;
	int ret = 0;
	char sql[SQL_LENGTH];

	memset(result, 0, sizeof(sql));
	memset(result, 0, n );

	if (mysql_query(g_server.conn, sql)) {
		zlog_error(logger, "mysql_query '%s' failed: %s", sql, mysql_error(g_server.conn));
		return FAIL;
	}

  res = mysql_use_result(g_conn);   //初始化逐行的结果集检索
	if ( NULL == res ) {
		zlog_error(logger, "mysql_use_result of '%s' failed: %s", sql, mysql_error(g_server.conn));
		return FAIL;
	}

	ix = 0;
	while ((row = mysql_fetch_row(res)) && ix < n) {//从结果集中获取下一行
		//申请空间，存储元素
		result[ix] = (void *)calloc(1, strlen(row[0]) + strlen(row[1]) + strlen(row[2]) + strlen(row[3]) + 4); //多申请2个字节是为了
															//1、'\0'
															//2、以后对目录标准化处理, 增加'/'
		if ( NULL == result[ix] ) {
			syslog(LOG_ERR, "%s:%d: fetch data from results of database failed:%s", 
					__FUNCTION__, __LINE__, mysql_error(g_conn)); 
			DEBUGLOG(printf("%s:%d: fetch data from results of database .......failed:%s\n", 
					__FUNCTION__, __LINE__, mysql_error(g_conn)));
			ret = -1;
			goto ERR_RET;
		}
//		memcpy(result[ix], row[0], strlen(row[0]));
		sprintf((char *)result[ix], "%s#%s#%s#%s", (char *)row[0], (char *)row[1], (char *)row[2], (char *)row[3]);
//		printf("%s\n", (char *)result[ix]);
 	 	ix++;
  	}
	mysql_free_result(res); //释放结果集
	

ERR_RET:
	if (-1 == ret) { //出错处理
/*
		for(ix = 0; result[ix] && ix < n; ix++) {
			free(result[ix]);
		}
*/
		return -1;
	}
	
	return ix;	
}

int fetch_record(void ** result, int unsigned n)
{
	return ops_mysql_query(result, n);
}

#endif


/*************************************************************/
#if 0
int main(int argc, char * argv[])
{
	MYSQL * conn;
	char ** result;
	int ret;
	if(ops_mysql_connect(&conn, MYSQL_IP, 3306, DB_NAME, 1) == NULL)
	{
		fprintf(stderr, "connect failed\n");
		return 1;
	}
	
	char select_db[] = "use falcon;";
	ret = ops_mysql_exec(conn, select_db);
	if(ret != 0)
	{
		fprintf(stderr, "db select failed\n");
		return 1;
	}

	result = (char **)calloc(1, sizeof(char *) * 2489482);
	char select_content[] = "select * from moni_data_minute where id < 2489482;";
	ops_mysql_query(conn, select_content, (void **)result, 2489482);

	free(result);

	return 0;
}
#endif
