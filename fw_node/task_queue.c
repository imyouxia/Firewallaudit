#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include "task_queue.h"
#include "zlog.h"

#define ADD_NEW_TASK	"1"

static int set_fd_non_block(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		// LOG
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		// LOG
		return -1;
	}

	return 0;
}


void init_worker_task_queue(worker_task_queue_t * tq)
{
	assert(tq);
	struct epoll_event ev;
	tq->tasks_num = 0;
	INIT_LIST_HEAD(&(tq->head));
	pthread_mutex_init(&tq->lock, NULL);
	pthread_cond_init(&tq->cond, NULL);

	pipe(tq->pipes);
	set_fd_non_block(tq->pipes[0]);
	set_fd_non_block(tq->pipes[1]);
	tq->epfd = epoll_create(MAX_FDS);
	ev.events = EPOLLIN;
	ev.data.fd = tq->pipes[0];
	int ret = epoll_ctl(tq->epfd, EPOLL_CTL_ADD, tq->pipes[0], &ev);
}

void receive_notify(worker_task_queue_t * tq)
{
	char buff[1024];
	memset(buff, '\0', sizeof(buff));
	while(read(tq->pipes[0], buff, sizeof(buff)) > 0) {
		memset(buff, '\0', sizeof(buff));
	}
}

void notify(worker_task_queue_t * tq)
{
	write(tq->pipes[1], ADD_NEW_TASK, strlen(ADD_NEW_TASK));
}

static void add_task(worker_task_queue_t * tq, task_node_t * tn)
{
	pthread_mutex_lock(&tq->lock);
	list_add_tail(&tn->list, &tq->head);
	tq->tasks_num++;
	pthread_mutex_unlock(&tq->lock);
}

task_node_t * create_new_task(void)
{
	task_node_t * new_nd;
	new_nd = (task_node_t *)calloc(1, sizeof(task_node_t));
	if(new_nd == NULL)
		return NULL;

	new_nd->priority = 0;
	new_nd->execute = 0;
	new_nd->task_id = 0;
	new_nd->func = NULL;
	new_nd->tn_client_data_dump = NULL;
	new_nd->destroy_func = NULL;
	new_nd->client_data = NULL;
	new_nd->create_time = 0;
	INIT_LIST_HEAD(&new_nd->list);
	return new_nd;
}

task_node_t * task_node_dump(task_node_t * src_nd)
{
	task_node_t * new_nd;
	new_nd = create_new_task();
	assert(new_nd);
	new_nd->priority = src_nd->priority;
	new_nd->task_id = src_nd->task_id;
	new_nd->execute = src_nd->execute;
	new_nd->create_time = src_nd->create_time;
	new_nd->func = src_nd->func;
	new_nd->tn_client_data_dump = src_nd->tn_client_data_dump;
	new_nd->destroy_func = src_nd->destroy_func;

	if (src_nd->client_data && src_nd->tn_client_data_dump) {
		new_nd->client_data = src_nd->tn_client_data_dump(src_nd->client_data);
	}

	return new_nd;
}

void add_task_with_notify(worker_task_queue_t * tq, task_node_t * tn)
{
	add_task(tq, tn);
	notify(tq);
}

void add_task_without_notify(worker_task_queue_t * tq, task_node_t * tn)
{
	add_task(tq, tn);
}

unsigned long long tq_tasks_num(worker_task_queue_t * tq)
{
	unsigned long long tasks_num;
	pthread_mutex_lock(&tq->lock);
	tasks_num = tq->tasks_num;
	pthread_mutex_unlock(&tq->lock);
	return tasks_num;
}

void pop_task(worker_task_queue_t * tq, task_node_t ** tn)
{
	struct list_head * node = NULL;
	pthread_mutex_lock(&tq->lock);
	
//	if (tq->tasks_num > 0 && list_empty(&tq->head) == 0) {
	if (tq->tasks_num > 0) {
		node = tq->head.prev;
		if (node != &tq->head) {
			list_del_init(node);
			tq->tasks_num--;
			*tn = list_entry(node, task_node_t, list);
		}
	} else {
		*tn = NULL;
	}
	pthread_mutex_unlock(&tq->lock);
}

void delete_task_node(task_node_t ** tc)
{
	task_node_t * del_node;
	del_node = *tc;
	assert(del_node);
	if(del_node->client_data && del_node->destroy_func)
		del_node->destroy_func(del_node->client_data);

	free(del_node);
	*tc = NULL;
}

void delete_task_with_id(worker_task_queue_t * tq, task_node_t * del)
{
	unsigned long long del_id;
	time_t del_time;
	struct list_head * node = NULL;
	task_node_t * tn;

	del_id = del->task_id;
	del_time = del->create_time;
	pthread_mutex_lock(&tq->lock);
	for(node = tq->head.prev; node != &(tq->head); node = node->prev) {
		tn = list_entry(node, task_node_t, list);
		if (tn->task_id  == del_id && tn->create_time == del_time) {
			list_del_init(node);
			tq->tasks_num--;
			delete_task_node(&tn);
			break;
		}
	}

	pthread_mutex_unlock(&tq->lock);
}
