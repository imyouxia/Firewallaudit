#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "net.h"
#include "ae.h"
#include "task_queue.h"
#include "work_thread.h"
#include "list.h"
#include "redis.h"
#include "zlog.h"
#include "constant.h"
#include "inifile.h"
#include "via_ssh2.h"
#include "dict.h"
#include "cjson.h"
#include "task.h"

#define FIFO_PATH	"/tmp/fw_audit.fifo"
//#define FIFO_PATH	"fw_audit.fifo"
#define FILE_MODE	(O_CREAT)
#define HOUR_SECOND	3600

zlog_category_t * logger;
char * conf_buff;
extern dict * g_d;

void daemonize(void) {
	int fd;
	
	if (fork() != 0) exit(0); /* parent exits */
	setsid(); /* create a new session */
	
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
	    dup2(fd, STDIN_FILENO);
	    dup2(fd, STDOUT_FILENO);
	    dup2(fd, STDERR_FILENO);
	    if (fd > STDERR_FILENO) close(fd);
	}
}

/*
 *  日志等级使用zlog的默认的6个等级，分别是
 *	"DEBUG", "INFO", "NOTICE", "WARN", "ERROR"和"FATAL"
 */

// 通过FIFO，通知获取新任务
static void handle_update(struct ae_event_loop * ev_lp, int fd,
								void * client_data, int mask)
{
	char * enter = NULL;
	size_t total_bytes = 0;
	size_t bytes = 0;
	char time_str[128];
	memset(time_str, '\0', sizeof(time_str));

	read(fd, time_str, sizeof(time_str));
	if ((enter = strchr(time_str, '\n')) != NULL)
		*enter = '\0';

	zlog_debug(logger, "New notification arrival: %s", time_str);
	load_redis_task(time_str, ev_lp);
}

static int init_conn_with_fifo(ae_event_loop * ev_lp)
{
	int readfd;
	unlink(FIFO_PATH);
	int retv;
	retv  = mkfifo(FIFO_PATH, O_RDWR);
	if (retv < 0) {
		zlog_error(logger, "mkfifo failed: %s", strerror(errno));
		return FAIL;
	}
	readfd = open(FIFO_PATH, O_RDWR | O_NONBLOCK);
	
	retv = ae_create_file_event(ev_lp, readfd, AE_READABLE, handle_update, NULL, NULL);
	if (retv == AE_ERR) {
		zlog_error(logger, "create listen fifo event failed");
		return FAIL;
	}

	chmod(FIFO_PATH, S_IRWXU | S_IRWXG | S_IRWXO);
	return OK;
}


static void handle_feedback(struct ae_event_loop * ev_lp, int fd,
								void * client_data, int mask)
{
	char * begin, * end;
	char cli_addr[16];
	int cli_port;
	int ret; int sign = -1;
	char buff[2048];

	memset(buff, '\0', sizeof(buff));
	memset(cli_addr, '\0', sizeof(cli_addr));

	int sockfd = 0;
	sockfd = net_tcp_accept(fd, cli_addr, &cli_port);
	if (sockfd < 0) {
		zlog_error(logger, "net_tcp_accept failed");
		sign = 0;
		goto ERR;
	}

	if ((ret = read(sockfd, buff, sizeof(buff))) > 0) {
		zlog_info(logger, "[READ FROM %s]: %s", cli_addr, buff);
	} else if (ret == 0) {
		zlog_info(logger, "[%s HAS CLOSED CONNECTION]", cli_addr);
	} else {
		zlog_error(logger, "[READ FROM %s SOCKET FAILED]", cli_addr);
		sign = 1;
		goto ERR;
	}

	char * tmp = strchr(buff, ':');
	char * key = NULL;
	if (tmp) {
		key = tmp + 1;
		zlog_info(logger, "[RECEIVE TASK_ID]: %s", key);
	} else {
		sign = 2;
		goto ERR;
	}

	char * value = NULL;
	value = (char *)dictFetchValue(g_d, tmp + 1);
	if (value == NULL) {
		zlog_error(logger, "[DICT HAS NO KEY:%s]", key);
		sign = 3;
		goto ERR;
	}

	zlog_info(logger, "[FETCH] KEY: %s VAL: %s\n", key, value);
	cJSON * root = NULL;
	root = cJSON_Parse(value);
	if (root == NULL) {
		zlog_error(logger, "[JSON PARSE FAILED] %s", value);
		sign = 4;
		goto ERR;
	}

	if (cJSON_GetObjectItem(root, "task_type") == NULL) {
		zlog_error(logger, "fetch task_type from json failed");
		sign = 5;
		goto ERR;
	}
	int task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

	if (cJSON_GetObjectItem(root, "dev_id") == NULL) {
		zlog_error(logger, "fetch dev_id from json failed");
		sign = 6;
		goto ERR;
	}
	int dev_id = cJSON_GetObjectItem(root, "dev_id")->valueint;

	if (task_type == FETCH_CFG) {
		memset(buff, '\0', sizeof(buff));
		char * localpath = strdup(cJSON_GetObjectItem(root, "localpath")->valuestring);
		FILE * fp = fopen(localpath, "w+");
		if (fp == NULL) {
			zlog_error(logger, "[FILE OPEN FAILED] %s", strerror(errno));
			free(localpath);
			sign = 7;
			goto ERR;
		}

		int nread;
		while((nread = read(sockfd, buff, sizeof(buff))) > 0) {
			fwrite(buff, sizeof(char), nread, fp);
			memset(buff, '\0', sizeof(buff));
		}

		free(localpath);
		fclose(fp);

	  char sql[1024]; memset(sql, '\0', sizeof(sql));
		snprintf(sql, sizeof(sql), "UPDATE cfg_info SET cfg_state=%d WHERE dev_id=%d", 1, dev_id);
		ops_mysql_exec_modify(sql);
	} else if (task_type == AUTO_OPTIMIZE) {
	  char sql[1024]; memset(sql, '\0', sizeof(sql));
		if (cJSON_GetObjectItem(root, "cmd") == NULL) {
			zlog_error(logger, "[fetch cmd from json failed]");
			sign = 8;
			goto ERR;
		}
		strcpy(sql, cJSON_GetObjectItem(root, "cmd")->valuestring);
		zlog_info(logger, "[CMD EXECUTE SUCCESSFULLY]: %s", sql);
	}

ERR:
	if (sockfd > 0 && (sign > 0 || sign == -1))	close(sockfd);
	if (value != NULL && (sign > 3 || sign == -1)) {
		zlog_info(logger, "DELETE key:%s value:%s FROM DICT", key, value);
		dictDelete(g_d, key);
	}
	if (root != NULL && (sign > 4 || sign == -1)) cJSON_Delete(root);
}

static int create_tcp_server(ae_event_loop * ev_lp, int sockfd)
{
	int retv;
	
	retv = ae_create_file_event(ev_lp, sockfd, AE_READABLE, handle_feedback, NULL, NULL);
	if (retv == AE_ERR) {
	        zlog_error(logger, "create listen fifo event failed");
	        return FAIL;
	}
	
	return OK;
}

static int tcp_server(void)
{
	int port = read_profile_int("local_audit", "listen_port", 9528, conf_buff);
	int listen_sockfd = net_tcp_server(port, NULL);
	return listen_sockfd;
}

//完成ae_loop的初始化
static ae_event_loop * ae_loop_init(void)
{
	ae_event_loop * ev_lp;
	ev_lp = ae_create_event_loop(1024);
	if (ev_lp == NULL) {
		zlog_error(logger, "ae loop create failed");
		return NULL;
	}
	return ev_lp;
}

static int log_init(const char * conf)
{
	int rc;
	rc = zlog_init(conf);
	if (rc) {
		fprintf(stderr, "log init failed\n");	
		return FAIL;
	}
	logger = zlog_get_category("audit");
	if (!logger) {
		fprintf(stderr, "zlog_get_category failed\n");
		return FAIL;
	}
	return OK;
}

static int load_conf(const char * file)
{
	conf_buff = calloc(4096, sizeof(char));
	if (!conf_buff) {
		zlog_error(logger, "memory alloc failed");
		return FAIL;
	}

	int rc = load_ini_file(file, conf_buff);
	if (rc == FAIL) {
		free(conf_buff);
		zlog_error(logger, "load_ini_file failed");
		return FAIL;
	}
	return OK;
}

static int ssh2_init(void)
{
	int rc;

	rc = libssh2_init(0);
	if (rc != 0) {
		zlog_error(logger, "ssh2 init failed");
		return FAIL;
	}
	return OK;
}

//完成线程池的初始化
int main(int argc, char * argv[])
{
	int rc;
	ae_event_loop * ev_lp;

	if (argc != 2) {
		fprintf(stderr, "Usage:/home/fw_audit/bin/fw_audit/fw_audit /home/fw_audit/bin/fw_audit/fw_audit.conf\n");
		exit(1);
	}

	chdir("/home/fw_audit/bin/fw_audit");
	rc = log_init("log.conf");
	if (rc == FAIL) exit(1);

	daemonize();
//	signal(SIGCHLD, SIG_IGN); 
	init_thread_pool(3);
	rc = load_conf(argv[1]);
	if (rc == FAIL) exit(1);

	rc = load_redis_conf(conf_buff);
	if (rc == FAIL) exit(1);

	rc = load_mysql_conf(conf_buff);
	if (rc == FAIL) exit(1);

	rc = ssh2_init();
	if (rc == FAIL) exit(1);

	rc = init_hash_dict();
	if (rc == FAIL) exit(1);
	
	ev_lp = ae_loop_init();
	if (ev_lp == NULL) exit(1);

	int sockfd = tcp_server();
	if (create_tcp_server(ev_lp, sockfd) == FAIL) exit(1);

	if (init_conn_with_fifo(ev_lp) == FAIL) exit(1);
	ae_main(ev_lp);

	return 0;
}
