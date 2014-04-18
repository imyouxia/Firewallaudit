#ifndef __AE_H
#define __AE_H

#define AE_OK		0
#define AE_ERR	-1

#define AE_NONE				0
#define AE_READABLE		1
#define AE_WRITABLE		2

#define AE_FILE_EVENTS	1
#define AE_TIME_EVENTS	2
#define	AE_ALL_EVENTS		(AE_FILE_EVENTS | AE_TIME_EVENTS)
#define AE_DONT_WAIT		4

#define AE_NOMORE				-1

struct ae_event_loop;

typedef void ae_file_func(struct ae_event_loop * event_loop, 
														int fd, void * client_data, int mask);

typedef int ae_time_func(struct ae_event_loop * event_loop, 
														long long id, void * client_data);

typedef void ae_event_finalizer_func(struct ae_event_loop * event_loop, 
														void * client_data);

typedef void ae_before_sleep_func(struct ae_event_loop * event_loop);

// 时间事件结构，是一个链表
typedef struct ae_time_event {
	long long id;
	long when_sec;
	long when_ms;
	ae_time_func * time_func;
	void * client_data;
	ae_event_finalizer_func * finalizer_func;
	struct ae_time_event * next;
} ae_time_event;

/* Registered File Event*/
//文件事件结构，是一个数组
typedef struct ae_file_event {
	int mask;			// AE_READABLE or AE_WRITABLE
	ae_file_func * r_file_func;
	ae_file_func * w_file_func;
	void * client_data;
} ae_file_event;

// 表示即将执行的事件
typedef struct ae_fired_event {
	int fd;
	int mask;
} ae_fired_event;

typedef struct ae_event_loop {
	int maxfd; //当前注册的fd最大值，初始值是-1
	int setsize; //轮循的最大文件句柄+1
	long long time_event_next_id; //下一个定时事件编号
	time_t last_time; //上次轮循的时间
	ae_file_event  * events; //存放注册的io事件数组，数组大小为setsize
	ae_fired_event * fired; //已经轮循到的事件
	ae_time_event * time_event_head; //定时事件链表
	int stop; //循环是否停止
	void * api_data; //这是epoll/select/kqueue等用到的结构
	ae_before_sleep_func * beforesleep; //事件循环中每次处理事件之前调用
} ae_event_loop;


ae_event_loop * ae_create_event_loop(int setsize);
void ae_delete_event_loop(ae_event_loop * ev_loop);
void ae_stop(ae_event_loop * ev_loop);
int ae_create_file_event(ae_event_loop * ev_loop, int fd, int mask, 
					ae_file_func * r_file_func,
					ae_file_func * w_file_func,
					void * client_data);
void ae_delete_file_event(ae_event_loop * ev_loop, int fd, int mask);
int ae_get_file_events(ae_event_loop * ev_loop, int fd);
long long ae_create_time_event(ae_event_loop * ev_loop, long long milliseconds, ae_time_func * time_func, void * client_data, ae_event_finalizer_func * finalizer_func);
int ae_delete_time_event(ae_event_loop * ev_loop, long long id);
int ae_process_events(ae_event_loop * ev_loop, int flags);
int ae_wait(int fd, int mask, long long milliseconds);
void ae_main(ae_event_loop * ev_loop);
char * ae_get_api_name(void);
void ae_set_before_sleep_func(ae_event_loop * ev_loop, ae_before_sleep_func * beforesleep);
#endif
