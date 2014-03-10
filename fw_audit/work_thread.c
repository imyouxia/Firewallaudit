#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <assert.h>
#include <time.h>
#include "task_queue.h"
#include "work_thread.h"
//#include "zlog.h"

worker_thread_t * g_schedule;

static void * schedule_thread_func(void * client_data)
{
	int fds, num, i = 0, j = 0;
	unsigned long long tasks; 
	task_node_t * tn;
	struct epoll_event ev;
	struct epoll_event ev_list[MAX_EVENTS];
	threads_pool_t * pool;
	worker_thread_t * self;
	worker_thread_t * workers;
	task_node_t * new_task;

	pool = (threads_pool_t *)client_data;
	self = pool->schedule;
	workers = pool->workers;
	num = pool->workers_num;

	while(self->stop != 1) {
		fds = epoll_wait(self->tq->epfd, ev_list, MAX_EVENTS, 1000);
		for (i = 0; i < fds; i++) {

			if (self->tq->pipes[0] == ev_list[i].data.fd) {
				receive_notify(self->tq);
				tasks = tq_tasks_num(self->tq);
				while(tasks > 0) {
					pop_task(self->tq, &tn);
					if (tn == NULL) {
						break;
					}

					new_task = task_node_dump(tn);
					add_task_without_notify((workers + (j%num))->tq, new_task);
					j++;

					//什么样的任务需要删除
					delete_task_node(&tn);
					tasks--;
				}
			}
		}

		if(fds == 0 && tq_tasks_num(self->tq) > 0)
			notify(self->tq);
	}
}

static void * worker_thread_func(void * client_data)
{
	int fds, i, ret;
	task_node_t * tn;
	unsigned long long tasks;
	struct epoll_event ev;
	struct epoll_event ev_list[MAX_EVENTS];
	worker_thread_t * self;
	self = (worker_thread_t *)client_data;

	while(self->stop != 1) {
		fds = epoll_wait(self->tq->epfd, ev_list, MAX_EVENTS, 1000);

		tasks = tq_tasks_num(self->tq);
		while(tasks > 0) {
			pop_task(self->tq, &tn);
			if (tn == NULL) {
				break;
			}

			if (tn->func) {
				tn->func(tn->client_data);
			}
			delete_task_node(&tn);
			tasks--;
		}
	}
}

worker_thread_t * create_workers(int workers_num)
{
	int i;
	int num = workers_num;
	worker_thread_t * workers;
	worker_thread_t * curr_worker;
	workers = (worker_thread_t *)calloc(1, sizeof(worker_thread_t) * num);
	assert(workers);

	for(i = 0; i < num; i++) {
		curr_worker = workers + i;
		curr_worker->tq = (worker_task_queue_t *)calloc(1, sizeof(worker_task_queue_t));
		assert(curr_worker->tq);
		init_worker_task_queue(curr_worker->tq);
		curr_worker->stop = 0;
		pthread_create(&curr_worker->tid, NULL, worker_thread_func, (void *)(curr_worker));
	}

	return workers;
}

worker_thread_t * create_schedule(worker_thread_t * workers, int workers_num)
{
	int num = workers_num;
	threads_pool_t * tp;
	worker_thread_t * schedule;

	schedule = (worker_thread_t *)calloc(1, sizeof(worker_thread_t));
	assert(schedule);

	schedule->tq = (worker_task_queue_t *)calloc(1, sizeof(worker_task_queue_t));
	assert(schedule->tq);
	init_worker_task_queue(schedule->tq);

	tp = (threads_pool_t *)calloc(1, sizeof(threads_pool_t));
	assert(tp);
	tp->schedule = schedule;
	tp->workers = workers;
	tp->workers_num = workers_num;

	pthread_create(&schedule->tid, NULL, schedule_thread_func, (void *)(tp));

	return schedule;
}


void init_thread_pool(int work_num)
{
	worker_thread_t * workers;
	workers = create_workers(work_num);
	int i;
	for (i = 0; i < work_num; i++)
		init_worker_task_queue((workers + i)->tq);
	
	g_schedule = create_schedule(workers, work_num);
}

