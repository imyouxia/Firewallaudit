#ifndef __INCLUDE_THREAD_H
#define __INCLUDE_THREAD_H
#include "task_queue.h"

//任务线程类型
enum thread_type {
	WORK_THREAD = 0,	//任务工作(执行)线程
	SCHEDULE_THREAD,	//任务调度(分发)线程
	WATCH_THREAD			//待用
};

//线程通用结构信息
typedef struct worker_thread {
	worker_task_queue_t	*	tq;		//对应任务队列
	pthread_t			tid;					//保存线程tid
	unsigned int		stop;				//线程销毁标志
} worker_thread_t;

//线程池通用结构信息
typedef struct threads_pool {
	worker_thread_t * schedule;	//对应任务调度(分发)线程
	worker_thread_t * workers;	//对应任务工作(执行)线程
	unsigned int	  workers_num;
} threads_pool_t;

worker_thread_t * create_workers(int workers_num);
worker_thread_t * create_schedule(worker_thread_t * workers, int workers_num);
void init_thread_pool(int work_num);
#endif
