#ifndef __INCLUDE_REDIS_H
#define __INCLUDE_REDIS_H
#include <time.h>

#include "hiredis/hiredis.h"
#include "ae.h"

typedef struct redis_server_info {
	char * server_addr;
	short	 server_port;
	char   db_choice;
	struct timeval timeout;
	redisContext * conn;
	char * key;
} redis_server_info;


int load_redis_task(const char * time_str, struct ae_event_loop * ev_loop);
int load_redis_conf(const char * buff);

#endif
