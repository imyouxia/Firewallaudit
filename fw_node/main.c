#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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

#define TIME_INTERVAL	1000

zlog_category_t * logger;
char * conf_buff;

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

static void handle_update(struct ae_event_loop * ev_lp, int fd,
								void * client_data, int mask)
{
	char buff[1024];
	char cli_addr[16];
	int cli_port;

	memset(cli_addr, '\0', sizeof(cli_addr));
	memset(buff, '\0', sizeof(buff));
	int sockfd = net_tcp_accept(fd, cli_addr, &cli_port);

	zlog_debug(logger, "[Connection test from %s:%d]", cli_addr, cli_port);
	if (read(sockfd, buff, sizeof(buff))  > 0)
		zlog_debug(logger, "[Connection test from %s:%d] %s", cli_addr, cli_port, buff);

	close(sockfd);
}

static int create_tcp_server(ae_event_loop * ev_lp, int sockfd)
{
	int retv;
	
	retv = ae_create_file_event(ev_lp, sockfd, AE_READABLE, handle_update, NULL, NULL);
	if (retv == AE_ERR) {
		zlog_error(logger, "create listen fifo event failed");
		return FAIL;
	}

	return OK;
}

/*
 *  日志等级使用zlog的默认的6个等级，分别是
 *	"DEBUG", "INFO", "NOTICE", "WARN", "ERROR"和"FATAL"
 */

// 通过FIFO，通知获取新任务
static int time_event_loop(struct ae_event_loop * ev_lp, long long id,
								void * client_data)
{
	printf("Timeout\n");
	load_redis_task(NULL, ev_lp);
	return TIME_INTERVAL;
}

static int create_time_event_loop(ae_event_loop * ev_lp)
{
	int retv;

	retv = ae_create_time_event(ev_lp, TIME_INTERVAL, time_event_loop, (void *)conf_buff, NULL);
	if (retv == AE_ERR) {
		zlog_error(logger, "create listen fifo event failed");
		return FAIL;
	}

	return OK;
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

static int tcp_server(void)
{
	int port = read_profile_int("local_node", "listen_port", 9527, conf_buff);
	int listen_sockfd = net_tcp_server(port, NULL);
	return listen_sockfd;
}

//完成线程池的初始化
int main(int argc, char * argv[])
{
	int rc;
	ae_event_loop * ev_lp;

	if (argc != 2) {
		fprintf(stderr, "Usage: ./final fw_audit.conf\n");
		exit(1);
	}

	chdir("/root/lihan/fw_node");
	rc = log_init("log.conf");
	if (rc == FAIL) exit(1);

	daemonize();
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
	if (create_time_event_loop(ev_lp) == FAIL) exit(1);
	
	int sockfd = tcp_server();
	if (create_tcp_server(ev_lp, sockfd) == FAIL) exit(1);

	ae_main(ev_lp);

	return 0;
}
