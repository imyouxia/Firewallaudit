#ifndef __INCLUDE_TASK_H
#define __INCLUDE_TASK_H
#include "via_ssh2.h"
#include "cjson.h"
#include "ae.h"
#include "telnet.h"

#define TYPE_NUM	5

enum task_type {
	FETCH_CFG = 1,
	SINGLE_AUDIT,
	MULTI_AUDIT,
	NET_ANALYSE,
	AUTO_OPTIMIZE
};

typedef int (*task_func)(const char * task_info, struct ae_event_loop * ve_loop);

typedef struct cfg_fetch_info {
	int task_type;
	unsigned long long task_id;
	ssh2_dst_info * src_info;
	telnet_dst_info * telnet_src_info;
	char * cmd;
	char * prompt;
	char * local_path;
	int dev_id;
	int interval;
	int execute;
} cfg_fetch_info;

typedef struct auto_optimize_info {
	int task_type;
	unsigned long long task_id;
	int dev_id;
	ssh2_dst_info * src_info;
	telnet_dst_info * telnet_src_info;
	char * cmd;
	char * prompt;
	int interval;
	int execute;
} auto_optimize_info;



int execute_fetch_cfg_task(const char * task_info, struct ae_event_loop * ev_loop);
int execute_telnet_fetch_cfg_task(const char * task_info, struct ae_event_loop * ev_loop);
int execute_auto_optimize_task(const char * buff, struct ae_event_loop * ev_loop);
int execute_telnet_auto_optimize_task(const char * task_info, struct ae_event_loop * ev_loop);

#endif
