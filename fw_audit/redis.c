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

static redis_server_info g_server;
extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;


static int update_serial_task_info(const char * task_info);

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

	g_server.db_choice = read_profile_int("redis", "db", 0, buff);
	if (g_server.db_choice == FAIL) {
		zlog_error(logger, "redis server db fetch failed");
		free(g_server.server_addr);
		return FAIL;
	}
	zlog_debug(logger, "redis db choice: %d", g_server.db_choice);

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
			zlog_error(logger, "redis connect failed");
			return -1;
		}
	}
	
	redisReply * reply;
	reply = redisCommand(server->conn, "LRANGE %s 0 -1", time_str);
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

	int j;	char buf[2048];
	cJSON * root = NULL;
	cJSON * type_field = NULL;
	int task_type;
	for (j = 0; j < cnt; j++) {
		memset(buf, '\0', sizeof(buf));
		if (reply->element[j]->str == NULL)
			continue;
		strcpy(buf, reply->element[j]->str);
		zlog_debug(logger, "[NEW_TASK_INFO] %s", buf);
		root = cJSON_Parse(buf);
		if (root == NULL) {
			zlog_error(logger, "cJSON_Parse failed");
			continue;
		}

		int size;
		if((size = cJSON_GetArraySize(root)) > 2) {
			type_field = cJSON_GetObjectItem(root, "task_type");
			if (type_field == NULL) {
				zlog_error(logger, "[%s] cJSON_GetObjectItem  of task_type failed", buf);
				continue;
			}

			task_type = type_field->valueint;

			if (task_type == FETCH_CFG)
				execute_retransmit_task(buf, ev_loop);
			else if(task_type == AUTO_OPTIMIZE)
				execute_retransmit_task(buf, ev_loop);
			else if(task_type == SINGLE_AUDIT)
				execute_single_audit_task(buf, ev_loop);
		} else if(size == 2) {
			char num[3];
			int i;
			for(i = 1; i <= size; i++)	{
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
					if (task_type == FETCH_CFG)
						execute_retransmit_task(ptr, ev_loop);
					else if(task_type == AUTO_OPTIMIZE)
						execute_retransmit_task(ptr, ev_loop);
					else if(task_type == SINGLE_AUDIT)
						execute_single_audit_task(ptr, ev_loop);
					
					free(ptr);
				}
				sleep(3);
			}
			update_serial_task_info(buf);
		}

		cJSON_Delete(root);
	}

	freeReplyObject(reply);

	reply = redisCommand(server->conn, "DEL %s", time_str);
	freeReplyObject(reply);

	return 0;
}

static int update_serial_task_info(const char * task_info)
{
	retransmit_info * info = NULL;
	info = calloc(1, sizeof(retransmit_info));
	if (info == NULL) {
		zlog_error(logger, "memory allocated failed");
		return FAIL;
	}

	cJSON * root = NULL;
	cJSON * inner = NULL;
	root = cJSON_Parse(task_info);

	if (root == NULL) {
		zlog_error(logger, "json string parse failed");
		return FAIL;
	}

	char num[3];
	int size;
	if ((size = cJSON_GetArraySize(root)) == 2) {
		memset(num, '\0', sizeof(num));
		int i = 1;
		snprintf(num, sizeof(num), "%d", i);
		cJSON * inner;
		inner = cJSON_GetObjectItem(root, num);
		if (inner == NULL) {
			zlog_error(logger, "json string parse failed");
			return FAIL;
		}

		if (cJSON_GetObjectItem(inner, "dst_node") == NULL) {
			zlog_error(logger, "fetch dst_node failed\n");
			cJSON_Delete(root);
			free(info);
			return FAIL;
		}
		info->dst_addr = strdup(cJSON_GetObjectItem(inner, "dst_node")->valuestring);
	}

	redis_server_info * server = &g_server;
	int ret = 0;
	if (server->conn == NULL) {
		ret = redis_connect_timeout();
		if (ret < 0) {
			return -1;
		}
	}

	char new_time[32];
	memset(new_time, '\0', sizeof(new_time));
	info->create_time = time(NULL);
	sprintf(new_time, "%ld", info->create_time);

	redisReply * reply;
	reply = redisCommand(server->conn, "select 1");
	freeReplyObject(reply);

	reply = redisCommand(server->conn, "LPUSH %s %s", new_time, task_info);
	freeReplyObject(reply);
	
	reply = redisCommand(server->conn, "SET %s %s", info->dst_addr, new_time);
	zlog_debug(logger, "LPUSH %s %s", new_time, task_info);
	zlog_debug(logger, "[REDIS COMMAND] SET %s %s", info->dst_addr, new_time);
	freeReplyObject(reply);

	reply = redisCommand(server->conn, "select 0");
	freeReplyObject(reply);
	cJSON_Delete(root);
	cJSON_Delete(inner);
	free(info->dst_addr);
	free(info);

	return OK;
}

int update_remote_task_info(retransmit_info * task_info)
{
	redis_server_info * server = &g_server;
	int ret = 0;
	if (server->conn == NULL) {
		ret = redis_connect_timeout();
		if (ret < 0) {
			return -1;
		}
	}

	char new_time[32];
	memset(new_time, '\0', sizeof(new_time));
	sprintf(new_time, "%ld", task_info->create_time);

	redisReply * reply;
	reply = redisCommand(server->conn, "select 1");
	freeReplyObject(reply);

	reply = redisCommand(server->conn, "LPUSH %s %s", new_time, task_info->task_info);
	freeReplyObject(reply);
	
	reply = redisCommand(server->conn, "SET %s %s", task_info->dst_addr, new_time);
	zlog_debug(logger, "LPUSH %s %s", new_time, task_info->task_info);
	zlog_debug(logger, "[REDIS COMMAND] SET %s %s", task_info->dst_addr, new_time);
	freeReplyObject(reply);

	reply = redisCommand(server->conn, "select 0");
	freeReplyObject(reply);

	return OK;
}

