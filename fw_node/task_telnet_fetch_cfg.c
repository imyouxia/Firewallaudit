#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "task_queue.h"
#include "via_ssh2.h"
#include "task.h"
#include "ae.h"
#include "task_queue.h"
#include "work_thread.h"
#include "zlog.h"
#include "cjson.h"
#include "db_mysql.h"
#include "telnet.h"
#include "constant.h"

extern worker_thread_t * g_schedule;
extern zlog_category_t * logger;
extern char * conf_buff;

static int add_cfg_fetch_task(ae_event_loop * ev_loop, long long id, void * client_data)
{
	task_node_t * task_info;
	task_info = (task_node_t *)client_data;
	add_task_with_notify(g_schedule->tq, (task_node_t *)client_data);
	return task_info->interval;
}


static int create_cfg_fetch_task(task_node_t * task_info, ae_event_loop * ev_loop)
{
	ae_create_time_event(ev_loop, 1000, add_cfg_fetch_task, task_info, NULL);
}

static char * get_cfg_name(char * localpath)
{
        char * ptr;
        char * cfg_name;
        ptr = strrchr(localpath,'/');
        cfg_name = ptr + 1;
        return cfg_name;
}

static void * fetch_cfg(void * info)
{
	cfg_fetch_info * fetch_info;
	fetch_info = (cfg_fetch_info *)info;

	char * cfg_name;
	cfg_name = get_cfg_name(fetch_info->local_path);

	char tftp_path[256];
	memset(tftp_path, '\0', sizeof(tftp_path));

	char * path = "/home/fw_audit/tftpboot/";
	strcpy(tftp_path, path);
	strcat(tftp_path, cfg_name);

	telnet(fetch_info->telnet_src_info, fetch_info->cmd, cfg_name);
	
	char buff[1024]; memset(buff, '\0', sizeof(buff));
	char sql[1024]; memset(sql, '\0', sizeof(sql));
	snprintf(sql, sizeof(sql), "UPDATE cfg_info SET cfg_state=%d WHERE dev_id=%d", 1, fetch_info->dev_id);
	ops_mysql_exec_modify(sql);

	char * remote_audit_ip;
	read_profile_string("remote_audit", "ip", &remote_audit_ip, "localhost", conf_buff);
	int remote_audit_port = read_profile_int("remote_audit", "listen_port", 9529, conf_buff);;

	int sockfd = net_tcp_connect(remote_audit_ip, remote_audit_port);
        if (sockfd < 0) {
		memset(sql, '\0', sizeof(sql));
		snprintf(sql, sizeof(sql), "UPDATE cfg_info SET cfg_update_state=%d WHERE dev_id=%d", 2, fetch_info->dev_id);
		ops_mysql_exec_modify(sql);

                zlog_error(logger, "[SOCKET CREATE FAILED]: %s", strerror(errno));
                free(remote_audit_ip);
                return NULL;
        }


	FILE * fp = fopen(tftp_path, "r");
        if (fp == NULL) {
                zlog_error(logger, "[FILE OPEN FAILED]: %s", strerror(errno));
                close(sockfd);
                free(remote_audit_ip);
                return NULL;
        }
	memset(sql, '\0', sizeof(sql));
	snprintf(sql, sizeof(sql), "[TASK_ID]:%llu", fetch_info->task_id);
	size_t nread = 0;
	if (sockfd > 0) {
		write(sockfd, sql, strlen(sql));
		zlog_info(logger, "[SEND TASK_ID]:%d", fetch_info->task_id);
	}
	else
	{
		memset(sql, '\0', sizeof(sql));
		snprintf(sql, sizeof(sql), "UPDATE cfg_info SET cfg_update_state=%d WHERE dev_id=%d", 1, fetch_info->dev_id);
		ops_mysql_exec_modify(sql);

		zlog_info(logger,"[remote_connect]:ip %s port %s",remote_audit_ip, remote_audit_port);
                free(remote_audit_ip);
                close(sockfd);
                fclose(fp);
                return NULL;
	}
	memset(buff, '\0', sizeof(buff));
	while((nread = fread(buff, sizeof(char), 1024, fp)) > 0) {
		write(sockfd, buff, nread);
	}
	close(sockfd);

	fclose(fp);

	memset(sql, '\0', sizeof(sql));
	snprintf(sql, sizeof(sql), "UPDATE cfg_info SET cfg_update_state=%d WHERE dev_id=%d", 1, fetch_info->dev_id);
	ops_mysql_exec_modify(sql);

	unlink(fetch_info->local_path);

	char deldir[1024]; memset(deldir, '\0', sizeof(deldir));
	strcpy(deldir, fetch_info->local_path);
	char * temp = strrchr(deldir, '/');
	if (temp) *temp = '\0';
	memset(buff, '\0', sizeof(buff));
	snprintf(buff, sizeof(buff), "rm -rf %s", deldir);
	system(buff);
        zlog_info(logger, "[DELETE DIRECTORY] %s", buff);

	free(remote_audit_ip);
	return NULL;
}


static void * fetch_cfg_client_data_dump(void * client_data)
{
	cfg_fetch_info * info, * new_info;
	info = (cfg_fetch_info *)client_data;

	new_info = (cfg_fetch_info *)calloc(1, sizeof(cfg_fetch_info));
	if (!new_info)  {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}

	new_info->telnet_src_info = (telnet_dst_info *)calloc(1, sizeof(telnet_dst_info));
	if (!new_info->telnet_src_info) {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}
	new_info->telnet_src_info->hostname = strdup(info->telnet_src_info->hostname);

	new_info->telnet_src_info->username = strdup(info->telnet_src_info->username);

	new_info->telnet_src_info->password = strdup(info->telnet_src_info->password);

	new_info->cmd = strdup(info->cmd);
	new_info->prompt = strdup(info->prompt);

	new_info->local_path = strdup(info->local_path);

	new_info->task_type = info->task_type;
	new_info->execute = info->execute;
	new_info->task_id = info->task_id;
	new_info->telnet_src_info->port = info->telnet_src_info->port;
	new_info->interval = info->interval;
	new_info->dev_id = info->dev_id;

	return new_info;
}


static void fetch_cfg_client_data_destroy(void * client_data)
{
	cfg_fetch_info * info;
	info = (cfg_fetch_info *)client_data;

	if(info->telnet_src_info->hostname) free(info->telnet_src_info->hostname);
	if(info->telnet_src_info->username) free(info->telnet_src_info->username);
	if(info->telnet_src_info->password) free(info->telnet_src_info->password);
	if(info->cmd) free(info->cmd);
	if(info->prompt) free(info->prompt);
	if(info->local_path) free(info->local_path);
	free(info->telnet_src_info);
	free(client_data);
}

static task_node_t * create_fetch_cfg_task(cfg_fetch_info * info)
{
	task_node_t * task = create_new_task();
	if (task == NULL) {
		zlog_error(logger, "create task failed");
		return NULL;
	}
	task->priority = 0;
	task->task_id = 0;
	task->interval = info->interval;
	task->execute = info->execute;
	task->func = fetch_cfg;
	task->tn_client_data_dump = fetch_cfg_client_data_dump;
	task->destroy_func = fetch_cfg_client_data_destroy;
	task->create_time = time(NULL);
	task->client_data = (void *)info;
	return task;
}

static cfg_fetch_info * parse_fetch_cfg_task(const char * task_info)
{
	if (strstr(task_info, ":null")) {
		zlog_error(logger, "[JSON STRING ERROR]: %s", task_info);
		return NULL;
	}

	cfg_fetch_info * info;
	
	info = calloc(1, sizeof(cfg_fetch_info));
	if (info == NULL) {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}

	info->telnet_src_info = calloc(1, sizeof(telnet_dst_info));
	if (info->telnet_src_info == NULL) {
		zlog_error(logger, "memory allocated failed");
		return NULL;
	}
	
	cJSON * root;
	root = cJSON_Parse(task_info);
	if (root == NULL) {
		zlog_error(logger, "cJSON_Parse failed");
		free(info->telnet_src_info);
		free(info);
		return NULL;
	}

	if (cJSON_GetObjectItem(root, "task_type") == NULL) {
		zlog_error(logger, "task_type is empty");
		free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->task_type = cJSON_GetObjectItem(root, "task_type")->valueint;

	info->execute = cJSON_GetObjectItem(root, "execute")->valueint;

	if (cJSON_GetObjectItem(root, "task_id") == NULL) {
		zlog_error(logger, "task_id is empty");
                free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->task_id = (unsigned long long)cJSON_GetObjectItem(root, "task_id")->valueint;

	if (cJSON_GetObjectItem(root, "hostname") == NULL) {
		zlog_error(logger, "hosename is empty");
                free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->telnet_src_info->hostname = strdup(cJSON_GetObjectItem(root, "hostname")->valuestring);
        if (info->telnet_src_info->hostname == NULL) {
                cJSON_Delete(root);
                free(info->telnet_src_info);
                free(info);
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                return NULL;
        }


	if (cJSON_GetObjectItem(root, "username") == NULL) {
		zlog_error(logger, "username is empty");
		free(info->telnet_src_info->hostname);
                free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->telnet_src_info->username = strdup(cJSON_GetObjectItem(root, "username")->valuestring);
        if (info->telnet_src_info->username == NULL) {
                cJSON_Delete(root);
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info);
                free(info);
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                return NULL;
        }

	if (cJSON_GetObjectItem(root, "password") == NULL) {
		zlog_error(logger, "password is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->telnet_src_info->password = strdup(cJSON_GetObjectItem(root, "password")->valuestring);
        if (info->telnet_src_info->password == NULL) {
                cJSON_Delete(root);
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info);
                free(info);
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                return NULL;
        }

	if (cJSON_GetObjectItem(root, "port") == NULL) {
		zlog_error(logger, "port is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->telnet_src_info);
		free(info);
		cJSON_Delete(root);
		return NULL;
	}
	info->telnet_src_info->port = cJSON_GetObjectItem(root, "port")->valueint;

        if (cJSON_GetObjectItem(root, "cmd") == NULL) {
                zlog_error(logger, "cmd is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->telnet_src_info);
                free(info);
                cJSON_Delete(root);
                return NULL;
        }
	info->cmd = strdup(cJSON_GetObjectItem(root, "cmd")->valuestring);
        if(info->cmd == NULL)
        {
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                cJSON_Delete(root);
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->telnet_src_info);
                free(info);
                return NULL;

        }

        if (cJSON_GetObjectItem(root, "prompt") == NULL) {
                zlog_error(logger, "prompt is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->cmd);
                free(info->telnet_src_info);
                free(info);
                cJSON_Delete(root);
                return NULL;
        }
	info->prompt = strdup(cJSON_GetObjectItem(root, "prompt")->valuestring);
        if (info->prompt == NULL) {
                cJSON_Delete(root);
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->cmd);
                free(info->telnet_src_info);
                free(info);
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                return NULL;
        }

        if (cJSON_GetObjectItem(root, "localpath") == NULL) {
                zlog_error(logger, "localpath is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->cmd);
                free(info->prompt);
                free(info->telnet_src_info);
                free(info);
                cJSON_Delete(root);
                return NULL;
        }
	info->local_path = strdup(cJSON_GetObjectItem(root, "localpath")->valuestring);
        if (info->local_path == NULL) {
                cJSON_Delete(root);
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->local_path);
                free(info->cmd);
                free(info->telnet_src_info);
                free(info);
                zlog_error(logger, "[MEMORY ALLOCATED FAILED]");
                return NULL;
        }

        if (cJSON_GetObjectItem(root, "dev_id") == NULL) {
                zlog_error(logger, "dev_id is empty");
                free(info->telnet_src_info->hostname);
		free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->local_path);
                free(info->cmd);
                free(info->telnet_src_info);
                free(info);
                cJSON_Delete(root);
                return NULL;
        }
	info->dev_id = cJSON_GetObjectItem(root, "dev_id")->valueint;

        if (cJSON_GetObjectItem(root, "task_interval") == NULL) {
                zlog_error(logger, "task_interval is empty");
                free(info->telnet_src_info->hostname);
                free(info->telnet_src_info->username);
                free(info->telnet_src_info->password);
                free(info->local_path);
                free(info->cmd);
                free(info->telnet_src_info);
                free(info);
                cJSON_Delete(root);
                return NULL;
        }

	info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint);

	if (info->interval > 0)
		info->interval = (cJSON_GetObjectItem(root, "task_interval")->valueint) * 60 * 1000;
	else if(info->interval == -1)
		info->interval = AE_NOMORE;

	zlog_debug(logger, "[TASK_TYPE]:fetch_cfg [HOSTNAME]:%s [USERNAME]:%s [PASSWORD]:%s"
				"[PORT]:%d [CMD]:%s [PROMPT]:%s [LOCALPATH]:%s [DEV_ID]:%d [INTERVAL]:%d",
				info->telnet_src_info->hostname, info->telnet_src_info->username, 
				info->telnet_src_info->password, info->telnet_src_info->port,
				info->cmd, info->prompt, info->local_path, 
				info->dev_id, info->interval);
	cJSON_Delete(root);
	return info;
}

int execute_telnet_fetch_cfg_task(const char * task_info, struct ae_event_loop * ev_loop)
{
	task_node_t * task = NULL;
	cfg_fetch_info * info = NULL;
	
	info = parse_fetch_cfg_task(task_info);
	if (!info) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", task_info);
		return FAIL;
	}
	task = create_fetch_cfg_task(info);
	if(!task) {
		zlog_error(logger, "[ADD TASK FAILED]: %s", task_info);
		return FAIL;
	}
	create_cfg_fetch_task(task, ev_loop);
	return OK;
}
