#ifndef __INCLUDE_TASK_QUEUE_H
#define __INCLUDE_TASK_QUEUE_H

#include <time.h>
#include <pthread.h>
#include "list.h"

#define MAX_FDS			1000
#define MAX_EVENTS		10000
#define HOUR_SECONDS	3600

//任务执行方式
enum execute_type {
	FOREVER = -1,			//表示该任务不停地执行
	ONCE,							//表示该任务只执行一次
	INTERVAL					//表示该任务按时间间隔执行
};

typedef void * task_fun(void * client_data);
typedef void * client_data_dump(void * client_data);
typedef void destroy_data(void * client_data);

typedef struct task_node {
	int execute;
	unsigned int								priority;			//指定任务优先级
	unsigned long long					task_id;			//任务ID
	time_t									create_time;		//任务创建时间
	int											interval;				//任务执行间隔
	task_fun 						*	func;						//实际执行任务回调函数
	client_data_dump	*	tn_client_data_dump;	//用户数据dump回调函数
	destroy_data		*	destroy_func;	//任务销毁时用户数据清理函数
	void				* 	client_data;		//用户自定义数据
	struct list_head 		list;				//连接任务队列
} task_node_t;


//任务队列
typedef struct worker_task_queue {
	//互斥锁保证任务添加、删除同步
	pthread_mutex_t		lock;
	//待用
	pthread_cond_t		cond;
	//IO复用接口epoll句柄
	int					epfd;
	//使用管道作为通知渠道
	int					pipes[2];
	//当前任务队列中的任务数
	unsigned long long	tasks_num;
	//任务队列
	struct list_head	head;
} worker_task_queue_t;


void init_worker_task_queue(worker_task_queue_t * tq);
void add_task_with_notify(worker_task_queue_t * tq, task_node_t * tn);
void add_task_without_notify(worker_task_queue_t * tq, task_node_t * tn);
void pop_task(worker_task_queue_t * tq, task_node_t ** tc);
void receive_notify(worker_task_queue_t * tq);
void delete_task_node(task_node_t ** tc);
void notify(worker_task_queue_t * tq);
task_node_t * create_new_task(void);
void delete_task_with_id(worker_task_queue_t * tq,  task_node_t * del_nd);
task_node_t * task_node_dump(task_node_t * src_nd);

unsigned long long tq_tasks_num(worker_task_queue_t * tq);
#endif
