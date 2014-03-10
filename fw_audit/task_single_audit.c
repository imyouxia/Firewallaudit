#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "task_queue.h"
#include "task.h"
#include "ae.h"
#include "task_queue.h"
#include "work_thread.h"
#include "zlog.h"
#include "cjson.h"
#include "db_mysql.h"
#include "constant.h"


extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;


static int add_single_audit_task(ae_event_loop * ev_loop, long long id, void * client_data)
{
	task_node_t * task_info;
	task_info = (task_node_t *)client_data;
	add_task_with_notify(g_schedule->tq, (task_node_t *)client_data);
	return task_info->interval;
}


static int create_audit_task(task_node_t * task_info, ae_event_loop * ev_loop)
{
	ae_create_time_event(ev_loop, 1000, add_single_audit_task, task_info, NULL);
}


static void * single_audit(void * info)
{
	single_audit_info * audit_info;
	audit_info = (single_audit_info *)info;

	char cmd[1024];

	memset(cmd, '\0', sizeof(cmd));
	
	if (strstr(audit_info->brand, "VENS"))
		snprintf(cmd, sizeof(cmd), "/usr/bin/perl %s VENS %s %d %s", audit_info->script_path, audit_info->cfg_path, audit_info->audit_task_id, audit_info->audit_id);
	else if (strstr(audit_info->brand, "TOPS"))
		snprintf(cmd, sizeof(cmd), "/usr/bin/perl %s TOPS %s %d %s", audit_info->script_path, audit_info->cfg_path, audit_info->audit_task_id, audit_info->audit_id);

	FILE * fp = popen(cmd, "r");
	pclose(fp);
	zlog_debug(logger, "[SINGLE AUDIT] %s", cmd);
	return NULL;
}


static void * single_audit_client_data_dump(void * client_data)
{
	single_audit_info * info, * new_info;
	info = (single_audit_info *)client_data;

	new_info = (single_audit_info *)calloc(1, sizeof(single_audit_info));
	if (!new_info) return NULL;
	new_info->task_type = info->task_type;
	new_info->dev_id = info->dev_id;
	new_info->task_id = info->task_id;
	new_info->audit_task_id = info->audit_task_id;
	new_info->interval = info->interval;

	new_info->script_path = strdup(info->script_path);
	new_info->cfg_path = strdup(info->cfg_path);
	new_info->audit_id = strdup(info->audit_id);
	new_info->brand = strdup(info->brand);

	return new_info;
}


static void single_audit_client_data_destroy(void * client_data)
{
	single_audit_info * info;
	info = (single_audit_info *)client_data;

	if (info->script_path) free(info->script_path);
	if (info->cfg_path) free(info->cfg_path);
	if (info->audit_id) free(info->audit_id);
	if (info->brand) free(info->brand);
	free(info);
}

static task_node_t * create_single_audit_task(single_audit_info * info)
{
	task_node_t * task = create_new_task();
	if (task == NULL) {
		zlog_error(logger, "create task failed");
		return NULL;
	}

	task->priority = 0;
	task->task_id = 0;
	task->interval = info->interval;
	task->func = single_audit;
	task->tn_client_data_dump = single_audit_client_data_dump;
	task->destroy_func = single_audit_client_data_destroy;
	task->create_time = time(NULL);
	task->client_data = (void *)info;

	return task;
}

static single_audit_info * parse_single_audit_task(const char * buff)
{
	cJSON * root;
	single_audit_info * info;
	info = calloc(1, sizeof(single_audit_info));
	if (info == NULL) {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}

	root = cJSON_Parse(buff);
	if (root == NULL) {
		zlog_error(logger, "cJSON_Parse failed");
		free(info);
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "task_type") == NULL) {
		zlog_error(logger, "task_type is empty");
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

	if (cJSON_GetObjectItem(root, "dev_id") == NULL) {
		zlog_error(logger, "dev_id is empty");
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->dev_id = cJSON_GetObjectItem(root, "dev_id")->valueint;

	if (cJSON_GetObjectItem(root, "task_id") == NULL) {
		zlog_error(logger, "task_id is empty");
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->task_id = cJSON_GetObjectItem(root, "task_id")->valueint;

	if (cJSON_GetObjectItem(root, "audit_task_id") == NULL) {
		zlog_error(logger, "audit_task_id is empty");
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->audit_task_id = cJSON_GetObjectItem(root, "audit_task_id")->valueint;

	if (cJSON_GetObjectItem(root, "script_path") == NULL) {
		zlog_error(logger, "script_path is empty");
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->script_path = strdup(cJSON_GetObjectItem(root, "script_path")->valuestring);
	if (info->script_path == NULL) {
		zlog_error(logger, "script_path is empty");
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "cfg_path") == NULL) {
		zlog_error(logger, "cfg_path is empty");
		free(info->script_path);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->cfg_path = strdup(cJSON_GetObjectItem(root, "cfg_path")->valuestring);
	if (info->cfg_path == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->script_path);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "audit_id") == NULL) {
		zlog_error(logger, "audit_id is empty");
		free(info->script_path);
		free(info->cfg_path);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->audit_id = strdup(cJSON_GetObjectItem(root, "audit_id")->valuestring);
	if (info->audit_id == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->script_path);
		free(info->cfg_path);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "brand") == NULL) {
		zlog_error(logger, "brand is empty");
		free(info->script_path);
		free(info->cfg_path);
		free(info->audit_id);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->brand = strdup(cJSON_GetObjectItem(root, "brand")->valuestring);
	if (info->brand == NULL) {
		zlog_error(logger, "memory allocated failed");
		free(info->script_path);
		free(info->cfg_path);
		free(info->audit_id);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "task_interval") == NULL) {
		zlog_error(logger, "task_interval is empty");
		free(info->script_path);
		free(info->cfg_path);
		free(info->audit_id);
		free(info->brand);
		free(info);
		cJSON_Delete(root);	
		return NULL;
	}
	info->interval = cJSON_GetObjectItem(root, "task_interval")->valueint;

	if (info->interval > 0)
		info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint) * 60 * 1000;
	else if(info->interval == -1)
		info->interval = AE_NOMORE;

	zlog_debug(logger, "[TASK_TYPE]:single_audit [SCRIPT_PATH]:%s"
						"[CFG_PATH]:%s [TASK_ID]:%d [AUDIT_ID]:%s [DEV_ID]:%d [INTERVAL]:%d [BRAND]:%s"
						"[AUDIT_TASK_ID]:%d",
						info->script_path, info->cfg_path, info->task_id, info->audit_id,
						info->dev_id, info->interval, info->brand, info->audit_task_id);

	cJSON_Delete(root);	
	return info;
}

int execute_single_audit_task(char * buff, struct ae_event_loop * ev_loop)
{
	task_node_t * task = NULL;
	single_audit_info * info = NULL;

	info = parse_single_audit_task(buff);
	if (info == NULL) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", buff);
		return FAIL;
	}
	task = create_single_audit_task(info);
	if (task == NULL) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", buff);
		return FAIL;
	}
	create_audit_task(task, ev_loop);

	return OK;
}
