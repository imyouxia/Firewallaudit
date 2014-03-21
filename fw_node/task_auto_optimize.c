#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "task_queue.h"
#include "via_ssh2.h"
#include "ae.h"
#include "task.h"
#include "task_queue.h"
#include "work_thread.h"
#include "zlog.h"
#include "cjson.h"
#include "db_mysql.h"
#include "constant.h"

extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;
extern char * conf_buff;

static int add_auto_optimize_task(ae_event_loop * ev_loop, long long id, void * client_data)
{
	task_node_t * task_info;
	task_info = (task_node_t *)client_data;
	add_task_with_notify(g_schedule->tq, (task_node_t *)client_data);
	return task_info->interval;
}

static int create_optimize_auto_task(task_node_t * task_info, ae_event_loop * ev_loop)
{
	ae_create_time_event(ev_loop, 1000, add_auto_optimize_task, task_info, NULL);
}

static void * auto_optimize(void * info)
{
	auto_optimize_info * cmd_info;
	cmd_info = (auto_optimize_info *)info;
	int ret = 0;

	char * delim = "&";
	char *temp_cmd;
	char cmd_full[128];
	memset(cmd_full,'\0', sizeof(cmd_full));
	strcpy(cmd_full, cmd_info->cmd);
	strtok(cmd_full, delim);
	
	ssh2_conn * conn;
	ret = ssh2_init_conn(cmd_info->src_info, &conn);

	if (ret == -1) {
		zlog_error(logger, "ssh2_init_conn failed");
		return NULL;
	}
	
	ret = cmd_exec_via_pseudoterm(conn, cmd_full, cmd_info->prompt, "/home/fw_audit/log/tmp");
	if (ret == -1) {
               zlog_error(logger, "cmd_exec_via_pseudoterm failed: %s", cmd_full);
               return NULL;
	}
                                       
	while(temp_cmd = (strtok(NULL, delim)))
	{
		zlog_info(logger, "[EXECUTE] %s", temp_cmd);
		ret = cmd_exec_via_pseudoterm(conn, temp_cmd, cmd_info->prompt, "/home/fw_audit/log/tmp");
		if (ret == -1) {
			// LOG
			return NULL;
		}
	}

	destroy_ssh2_conn(conn);

	char * remote_audit_ip;
	read_profile_string("remote_audit", "ip", &remote_audit_ip, "localhost", conf_buff);
	int remote_audit_port = read_profile_int("remote_audit", "listen_port", 9528, conf_buff);
	int sockfd = net_tcp_connect(remote_audit_ip, remote_audit_port);
	char sql[1024]; memset(sql, '\0', sizeof(sql));
	snprintf(sql, sizeof(sql), "[TASK_ID]:%llu", cmd_info->task_id);
	zlog_info(logger, "[SEND TASK_ID]: %llu", cmd_info->task_id);
	if (sockfd > 0) {
		write(sockfd, sql, strlen(sql));
		close(sockfd);
	} else {
		zlog_error(logger, "[CONNECT REMOTE_AUDIT:%s PORT:%d FAILED]", remote_audit_ip, remote_audit_port);
	}

	return NULL;
}

static void * auto_optimize_client_data_dump(void * client_data)
{
	auto_optimize_info * info, * new_info;
	info = (auto_optimize_info *)client_data;

	new_info = (auto_optimize_info *)calloc(1, sizeof(auto_optimize_info));
	if (!new_info) return NULL;
	new_info->src_info = (ssh2_dst_info *)calloc(1, sizeof(ssh2_dst_info));
	if (!new_info->src_info) return NULL;
	new_info->src_info->hostname = strdup(info->src_info->hostname);

	new_info->src_info->username = strdup(info->src_info->username);

	new_info->src_info->password = strdup(info->src_info->password);

	new_info->cmd = strdup(info->cmd);
	new_info->prompt = strdup(info->prompt);

	new_info->src_info->port = info->src_info->port;
	new_info->task_type = info->task_type;
	new_info->execute = info->execute;
	new_info->task_id = info->task_id;
	new_info->interval = info->interval;

	return new_info;
}

static void auto_optimize_client_data_destroy(void * client_data)
{
	auto_optimize_info * info;
	info = (auto_optimize_info *)client_data;

	if(info->src_info->hostname) free(info->src_info->hostname);
	if(info->src_info->username) free(info->src_info->username);
	if(info->src_info->password) free(info->src_info->password);
	if(info->cmd) free(info->cmd);
	if(info->prompt) free(info->prompt);
	free(info->src_info);
	free(client_data);
}

static task_node_t * create_auto_optimize_task(auto_optimize_info * info)
{
	task_node_t * task = create_new_task();
	if (task == NULL) {
		zlog_error(logger, "create_new_task failed");
		return NULL;
	}

	task->priority = 0;
	task->task_id = 0;
	task->interval = info->interval;
	task->execute = info->execute;
	task->func = auto_optimize;
	task->tn_client_data_dump = auto_optimize_client_data_dump;
	task->destroy_func = auto_optimize_client_data_destroy;
	task->create_time = time(NULL);
	task->client_data = (void *)info;
	return task;
}


static auto_optimize_info * parse_auto_optimize_task(const char * buff)
{
	if (strstr(buff, ":null")) {
		zlog_error(logger, "[JSON STRING ERROR]: %s", buff);
		return NULL;
	}

	cJSON * root = NULL;
	root = cJSON_Parse(buff);
	if (root == NULL) {
		zlog_error(logger, "[JSON PARSE FAILED]");
		return NULL;
	}

	auto_optimize_info * info = NULL;
	info = calloc(1, sizeof(auto_optimize_info));
	if (info == NULL) {
		cJSON_Delete(root);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	info->src_info = calloc(1, sizeof(ssh2_dst_info));
	if (info->src_info == NULL) {
		cJSON_Delete(root);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}
	
	if (cJSON_GetObjectItem(root, "task_type") == NULL) {
		cJSON_Delete(root);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH task_type FROM JSON FAILED]");
		return NULL;
	}
	info->task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

	info->execute = cJSON_GetObjectItem(root, "execute")->valueint;

	if (cJSON_GetObjectItem(root, "hostname") == NULL) {
		cJSON_Delete(root);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->src_info->hostname = strdup(cJSON_GetObjectItem(root, "hostname")->valuestring);
	if (info->src_info->hostname == NULL) {
		cJSON_Delete(root);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "username") == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->src_info->username = strdup(cJSON_GetObjectItem(root, "username")->valuestring);
	if (info->src_info->username == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "password") == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->src_info->password = strdup(cJSON_GetObjectItem(root, "password")->valuestring);
	if (info->src_info->password == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "port") == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info->password);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->src_info->port = cJSON_GetObjectItem(root, "port")->valueint;

	if (cJSON_GetObjectItem(root, "cmd") == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info->password);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->cmd = strdup(cJSON_GetObjectItem(root, "cmd")->valuestring);
	if (info->cmd == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info->password);
		free(info->src_info);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "prompt") == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info->password);
		free(info->src_info);
		free(info->cmd);
		free(info);
		zlog_error(logger, "[FETCH hostnmae FROM JSON FAILED]");
		return NULL;
	}
	info->prompt = strdup(cJSON_GetObjectItem(root, "prompt")->valuestring);
	if (info->prompt == NULL) {
		cJSON_Delete(root);
		free(info->src_info->hostname);
		free(info->src_info->username);
		free(info->src_info->password);
		free(info->src_info);
		free(info->cmd);
		free(info);
		zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
		return NULL;
	}

	info->dev_id = cJSON_GetObjectItem(root, "dev_id")->valueint;
	info->task_id = (cJSON_GetObjectItem(root, "task_id")->valueint);

	info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint);

	if (info->interval > 0)
		info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint) * 60 * 1000;
	else if(info->interval == -1)
		info->interval = AE_NOMORE;

	zlog_debug(logger, "[TASK_TYPE]:auto_optimize [HOSTNAME]:%s [USERNAME]:%s [PASSWORD]:%s"
										 "[PORT]:%d [CMD]:%s [DEV_ID]:%d [TASK_ID]:%llu",
											info->src_info->hostname, info->src_info->username, 
											info->src_info->password, info->src_info->port,
											info->cmd, info->dev_id, info->interval);

	cJSON_Delete(root);
	return info;
}



int execute_auto_optimize_task(const char * buff, struct ae_event_loop * ev_loop)
{
	task_node_t * task = NULL;
	auto_optimize_info * info = NULL;
	
	info = parse_auto_optimize_task(buff);
	if (info == NULL) {
		zlog_error(logger, "parse_auto_optimize_task failed");
		return FAIL;
	}

	task = create_auto_optimize_task(info);
	if (task  == NULL) {
		zlog_error(logger, "create_auto_optimize_task failed");
		return FAIL;
	}
	create_optimize_auto_task(task, ev_loop);
	zlog_info(logger, "[CREATE AUTO OPTIMIZE] %s", buff);

	return OK;
}

