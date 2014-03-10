#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "task_queue.h"
#include "via_ssh2.h"
#include "task.h"
#include "ae.h"
#include "task_queue.h"
#include "work_thread.h"
#include "zlog.h"
#include "cjson.h"
#include "db_mysql.h"
#include "dict.h"
#include "constant.h"

extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;
extern dict * g_d;

extern int update_remote_task_info(retransmit_info * task_info);

static int add_cfg_fetch_task(ae_event_loop * ev_loop, long long id, void * client_data)
{
	task_node_t * task_info;
	task_info = (task_node_t *)client_data;
	add_task_with_notify(g_schedule->tq, (task_node_t *)client_data);
zlog_info(logger, "add_task_with_notify once");
	return task_info->interval;
}

static int create_retransmit_task(task_node_t * task_info, ae_event_loop * ev_loop)
{
	ae_create_time_event(ev_loop, 10, add_cfg_fetch_task, task_info, NULL);
}


static void * retransmit(void * info)
{
	retransmit_info * task_info;
	task_info = (retransmit_info *)info;

	if (task_info->execute == PARALLEL)
		update_remote_task_info(task_info);

	return NULL;
}


static void * retransmit_data_dump(void * client_data)
{
	retransmit_info * info, * new_info;
	info = (retransmit_info *)client_data;

	new_info = (retransmit_info *)calloc(1, sizeof(retransmit_info));
	if (!new_info) return NULL;

	new_info->task_type = info->task_type;
	new_info->execute = info->execute;
	new_info->dst_addr = strdup(info->dst_addr);
	new_info->task_info = strdup(info->task_info);
	new_info->create_time = info->create_time;
	new_info->interval = info->interval;

	return new_info;
}

static void retransmit_data_destroy(void * client_data)
{
	retransmit_info * info;
	info = (retransmit_info *)client_data;

	if(info->dst_addr) free(info->dst_addr);
	if(info->task_info) free(info->task_info);

	free(client_data);
}

static task_node_t * create_retransmit_task_node(retransmit_info * info)
{
	task_node_t * task = create_new_task();
	if (task == NULL) {
		zlog_error(logger, "create task failed");
		return NULL;
	}

	task->execute = info->execute;
	task->priority = 0;
	task->task_id = 0;
	task->interval = info->interval;
	task->func = retransmit;
	task->tn_client_data_dump = retransmit_data_dump;
	task->destroy_func = retransmit_data_destroy;
	task->create_time = info->create_time;
	task->client_data = (void *)info;
	return task;
}

static retransmit_info * parse_retransmit_task(const char * task_info)
{
	retransmit_info * info = NULL;
	info = calloc(1, sizeof(retransmit_info));
	if (info == NULL) {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}

	cJSON * root = NULL;
	cJSON * type_field = NULL;
	root = cJSON_Parse(task_info);
	if (root == NULL) {
		zlog_error(logger, "json string parse failed");
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "task_type") == NULL) {
		zlog_error(logger, "fetch task_type failed\n");
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	info->task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

	if (cJSON_GetObjectItem(root, "execute") == NULL) {
		zlog_error(logger, "fetch execute failed\n");
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	info->execute = cJSON_GetObjectItem(root, "execute")->valueint;

	if (cJSON_GetObjectItem(root, "task_id") == NULL) {
		zlog_error(logger, "fetch task_id failed\n");
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	info->task_id = (unsigned long long)cJSON_GetObjectItem(root, "task_id")->valueint;

	if (cJSON_GetObjectItem(root, "dst_node") == NULL) {
		zlog_error(logger, "fetch dst_node failed\n");
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	info->dst_addr = strdup(cJSON_GetObjectItem(root, "dst_node")->valuestring);

	info->task_info = strdup(task_info);
	if (info->task_info == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->dst_addr);
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	info->create_time = time(NULL);

	info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint);

	if (info->interval > 0)
		info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint) * 60 * 1000;
	else if(info->interval == -1)
		info->interval = AE_NOMORE;

	zlog_debug(logger, "[TASK_TYPE]:retransmit_task [DST_ADDR]:%s "
										 "[TASK_INFO]:%s [INTERVAL]:%d",
											info->dst_addr, info->task_info, info->interval);

	char * key = calloc(1, sizeof(char) * 64);
	if (key == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->dst_addr);
		free(info->task_info);
		cJSON_Delete(root);
		free(info);
		return NULL;
	}
	snprintf(key, 64, "%llu", info->task_id);

	char * val = strdup(task_info);
	if (val == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->dst_addr);
		free(info->task_info);
		free(key);
		cJSON_Delete(root);
		free(info);
		return NULL;
	}

	if (dictAdd(g_d, key, val) == DICT_ERR) {
		zlog_error(logger, "memory allocated failed");
		free(info->dst_addr);
		free(info->task_info);
		free(key);
		free(val);
		cJSON_Delete(root);
		free(info);
		return NULL;
	}

	zlog_info(logger, "[ADD TO DICT] [KEY]:%s [VAL]:%s", key, val);
	cJSON_Delete(root);
	return info;
}

int execute_retransmit_task(const char * task_info, struct ae_event_loop * ev_loop)
{
	task_node_t * task = NULL;
	retransmit_info * info = NULL;
	info = parse_retransmit_task(task_info);
	if (info == NULL) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", task_info);
		return FAIL;	
	}

	task = create_retransmit_task_node(info);
	if (task == NULL) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", task_info);
		return FAIL;
	}
	zlog_info(logger, "[CREATE RETRANSMIT] %s", task_info);
	create_retransmit_task(task, ev_loop);
	return OK;
}
