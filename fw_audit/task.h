#ifndef __INCLUDE_TASK_H
#define __INCLUDE_TASK_H
#include "via_ssh2.h"
#include "cjson.h"
#include "ae.h"

#define TYPE_NUM	5

enum task_type {
	FETCH_CFG = 1,			// Need to be transfered
	SINGLE_AUDIT,
	MULTI_AUDIT,
	NET_ANALYSE,
	AUTO_OPTIMIZE				// Need to be transfered
};

typedef struct single_audit_info {
	int task_type;
	int dev_id;
	char * script_path;
	char * cfg_path;
	char * audit_id;
	char * brand;
	int task_id;
	int audit_task_id;
	int interval;
	int execute;
} single_audit_info;


typedef struct retransmit_info {
	int task_type;
	unsigned long long task_id;
	char * dst_addr;
	char * task_info;
	time_t create_time;
	int interval;
	int execute;
} retransmit_info;


int execute_retransmit_task(const char * task_info, struct ae_event_loop * ev_loop);

#endif
