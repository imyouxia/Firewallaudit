#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "hiredis/hiredis.h"
#include "redis.h"
#include "task_queue.h"
#include "work_thread.h"
#include "task.h"
#include "cjson.h"
#include "zlog.h"
#include "constant.h"
#include "telnet.h"

static redis_server_info g_server;
extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;
extern task_node_t * create_fetch_cfg_task(cfg_fetch_info * info);
extern int execute_telnet_fetch_cfg_task(const char * task_info, struct ae_event_loop * ev_loop);

static unsigned long long g_version;

int load_redis_conf(const char * buff)
{
	int retv;
	retv = read_profile_string("redis", "server", &g_server.server_addr, "localhost", buff);
	if (retv == FAIL) {
		zlog_error(logger, "redis server addr fetch failed");
		return FAIL;
	}
	zlog_debug(logger, "redis server addr: %s", g_server.server_addr);

	g_server.server_port = read_profile_int("redis", "port", 6379, buff);
	if (g_server.server_port == FAIL) {
		zlog_error(logger, "redis server port fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "redis server port: %d", g_server.server_port);

	g_server.db_choice = read_profile_int("redis", "db", 1, buff);
	if (g_server.db_choice == FAIL) {
		zlog_error(logger, "redis server db fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "redis db choice: %d", g_server.db_choice);

	retv = read_profile_string("local_node", "ip", &g_server.key, "localhost", buff);
	if (retv == FAIL) {
		zlog_error(logger, "redis server db fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "local ip as key: %s", g_server.key);

	g_server.timeout.tv_sec = 2;
	g_server.timeout.tv_usec = 0;
	g_server.conn = NULL;

	return OK;
}


static int redis_connect_timeout(void)
{
	redis_server_info * server = &g_server;
	redisReply * reply = NULL;
	
	server->conn = redisConnectWithTimeout(server->server_addr, server->server_port, server->timeout);
	if (server->conn->err) {
		zlog_error(logger, "connect to redis server[%s:%d] failed: %s", 
								server->server_addr, server->server_port, server->conn->errstr);	
		redisFree(server->conn);
		server->conn = NULL;
		return -1;
	}
	
	reply = redisCommand(server->conn, "SELECT %d", server->db_choice);
	freeReplyObject(reply);
	return 0;
}


int load_redis_task(const char * time_str, struct ae_event_loop * ev_loop)
{
	redis_server_info * server = &g_server;
	int ret = 0;
	if (server->conn == NULL) {
		ret = redis_connect_timeout();
		if (ret < 0) {
			return -1;
		}
	}

	redisReply * reply;
	reply = redisCommand(server->conn, "select 1");
	freeReplyObject(reply);
	
	unsigned long long version;
	printf("g_server.key = %s\n", g_server.key);
	reply = redisCommand(server->conn, "get %s", g_server.key);
	if (reply == NULL) {
		zlog_error(logger, "No elements with 'GET %s'", g_server.key);
		redisFree(server->conn);
		server->conn = NULL;
		return -1;
	}

	if (reply->str == NULL) {
		zlog_error(logger, "reply with null for 'GET %s'", g_server.key);
		redisFree(server->conn);
		server->conn = NULL;
		return -1;
	}

	version = strtol(reply->str, NULL, 10);
	freeReplyObject(reply);

	if (version > g_version) {
		g_version = version;
		redisReply * reply;
		reply = redisCommand(server->conn, "LRANGE %llu 0 -1", version);
		if (reply == NULL) {
			zlog_error(logger, "No elements with 'LRANGE %s 0 -1'", time_str);
			redisFree(server->conn);
			server->conn = NULL;
			return -1;
		}
	
		if (reply->type == REDIS_REPLY_NIL) {
			zlog_error(logger, "No elements with 'LRANGE %s 0 -1'", time_str);
			freeReplyObject(reply);
			return -1;
		}
	
		int cnt = reply->elements;
		if (cnt == 0) {
			zlog_error(logger, "No elements with 'LRANGE %s 0 -1'", time_str);
			freeReplyObject(reply);
			return -1;
		}
	
		int j;	char buf[1024];
		cJSON * root;
		cJSON * type_field;
		int task_type;
		for (j = 0; j < cnt; j++) {
			memset(buf, '\0', sizeof(buf));
			strcpy(buf, reply->element[j]->str); 
			zlog_debug(logger, "[NEW-TASK] %s", buf);

			root = cJSON_Parse(buf);
			int size;
	
			if ((size = cJSON_GetArraySize(root)) > 2) {
				task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

				if (task_type == FETCH_CFG) {
					if (strstr(cJSON_GetObjectItem(root, "protocol")->valuestring, "ssh"))
						execute_fetch_cfg_task(buf, ev_loop);
					else if (strstr(cJSON_GetObjectItem(root, "protocol")->valuestring, "telnet"))
						execute_telnet_fetch_cfg_task(buf, ev_loop);
				} else if(task_type == AUTO_OPTIMIZE) {
					if (strstr(cJSON_GetObjectItem(root, "protocol")->valuestring, "ssh"))
                	                        execute_auto_optimize_task(buf, ev_loop);
                	                else if (strstr(cJSON_GetObjectItem(root, "protocol")->valuestring, "telnet"))
                	                        execute_telnet_auto_optimize_task(buf, ev_loop);
				}
			} else if (size == 2) {
				char num[3];
				int i;
				for(i = 1; i <= size; i++)  {
					memset(num, '\0', sizeof(num));
					snprintf(num, sizeof(num), "%d", i); 
					cJSON * inner;
					inner = cJSON_GetObjectItem(root, num);

					type_field = cJSON_GetObjectItem(inner, "task_type");
					if (type_field == NULL) {
						zlog_error(logger, "[%s] cJSON_GetObjectItem  of task_type failed", buf);
						continue;
					}   

					task_type = type_field->valueint;
					char * ptr;
					ptr = cJSON_PrintUnformatted(inner);

					if (ptr != NULL) {
						zlog_info(logger, "[SPLIT TASK] %s", ptr);
						if (task_type == FETCH_CFG) {
							if (strstr(cJSON_GetObjectItem(inner, "protocol")->valuestring, "ssh"))
								execute_fetch_cfg_task(ptr, ev_loop);
							else if (strstr(cJSON_GetObjectItem(inner, "protocol")->valuestring, "telnet"))
								execute_telnet_fetch_cfg_task(ptr, ev_loop);
						} else if(task_type == AUTO_OPTIMIZE) {
							if (strstr(cJSON_GetObjectItem(inner, "protocol")->valuestring, "ssh"))
                			                        execute_auto_optimize_task(ptr, ev_loop);
                			                else if (strstr(cJSON_GetObjectItem(inner, "protocol")->valuestring, "telnet"))
                			                        execute_telnet_auto_optimize_task(ptr, ev_loop);
						}

						free(ptr);
					}
					//sleep(2);
				}
			}
			cJSON_Delete(root);
		}
	
		freeReplyObject(reply);
		reply = redisCommand(server->conn, "DEL %llu", version);
		freeReplyObject(reply);
	}

	return 0;
}

