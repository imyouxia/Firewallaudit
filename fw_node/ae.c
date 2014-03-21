#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ae.h"

#include "ae_select.c"


ae_event_loop * ae_create_event_loop(int setsize)
{
	ae_event_loop * event_loop = NULL;
	event_loop = (ae_event_loop *)calloc(1, sizeof(*event_loop));
	if (!event_loop)
		goto err_handle;

	event_loop->events = (ae_file_event *)calloc(setsize, sizeof(ae_file_event));
	event_loop->fired = (ae_fired_event *)calloc(setsize, sizeof(ae_fired_event));
	if (!event_loop->events || !event_loop->fired)
		goto err_handle;

	event_loop->maxfd = -1;
	event_loop->setsize = setsize;
	event_loop->stop = 0;

	event_loop->time_event_head = NULL;
	event_loop->last_time = time(NULL);
	event_loop->time_event_next_id = 0;
	event_loop->beforesleep = NULL;

	if (ae_api_create(event_loop) == AE_ERR) {
		//LOG here
		goto err_handle;
	}

	int i;
	for (i = 0; i < setsize; i++) {
		event_loop->events[i].mask = AE_NONE;
	}
	
	return event_loop;

err_handle:
	if (event_loop) {
		if(event_loop->events) free(event_loop->events);
		if(event_loop->fired) free(event_loop->fired);
		if(event_loop) free(event_loop);
	}
	return NULL;
}

void ae_delete_event_loop(ae_event_loop * ev_loop)
{
	ae_api_free(ev_loop);
	if (ev_loop->events) free(ev_loop->events);
	if (ev_loop->fired)  free(ev_loop->events);
	free(ev_loop->events);
}

void ae_stop(ae_event_loop * ev_loop)
{
	ev_loop->stop = 1;
}

int ae_create_file_event(ae_event_loop * ev_loop, int fd, int mask, 
													ae_file_func * r_file_func, 
													ae_file_func * w_file_func,
													void * client_data)
{
	if (fd >= ev_loop->setsize)	 {
		errno = ERANGE;
		return AE_ERR;
	}

	ae_file_event * fe = &ev_loop->events[fd];

	if (ae_api_add_event(ev_loop, fd, mask) == AE_ERR) {
		//LOG
		return AE_ERR;
	}

	fe->mask |= mask;
	if (mask & AE_READABLE) fe->r_file_func = r_file_func;
	if (mask & AE_WRITABLE) fe->w_file_func = w_file_func;

	fe->client_data = client_data;
	if (fd > ev_loop->maxfd)
		ev_loop->maxfd = fd;

	return AE_OK;
}

void ae_delete_file_event(ae_event_loop * ev_loop, int fd, int mask)
{
	if (fd >= ev_loop->setsize) return;
	ae_file_event * fe = &ev_loop->events[fd];

	if (fe->mask == AE_NONE) return;
	fe->mask &= (~mask);

	// Maybe fd still has a readable or writable event
	if (fd == ev_loop->maxfd && fe->mask == AE_NONE) {
		int j;
		// Update maxfd
		for (j = ev_loop->maxfd - 1; j >= 0; j--) {
			if (ev_loop->events[fd].mask != AE_NONE) {
				break;
			}
		}

		ev_loop->maxfd = j;
	}
	
	ae_api_del_event(ev_loop, fd, mask);
}

int ae_get_file_events(ae_event_loop * ev_loop, int fd)
{
	if (fd >= ev_loop->setsize) return AE_NONE;

	ae_file_event * fe = &ev_loop->events[fd];
	return fe->mask;
}

static void ae_get_time(long * seconds, long * milliseconds)
{
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	*seconds = tv.tv_sec;
	*milliseconds = tv.tv_usec / 1000;
}

static void ae_add_milliseconds_to_now(long long milliseconds, long * sec, long * ms)
{
	long cur_sec, cur_ms, when_sec, when_ms;

	ae_get_time(&cur_sec, &cur_ms);
	when_sec = cur_sec + milliseconds / 1000;
	when_ms = cur_ms + milliseconds % 1000;

	if (when_ms >= 1000) {
		when_sec++;
		when_ms -= 1000;
	}

	*sec = when_sec;
	*ms = when_ms;
}



long long ae_create_time_event(ae_event_loop * ev_loop, long long milliseconds, ae_time_func * time_func, void * client_data, ae_event_finalizer_func * finalizer_func)
{
	long long id = ev_loop->time_event_next_id++;
	ae_time_event * te;

	te = (ae_time_event *)calloc(1, sizeof(*te));
	if (te == NULL) return -1;

	te->id = id;
	ae_add_milliseconds_to_now(milliseconds, &te->when_sec, &te->when_ms);
	te->time_func = time_func;
	te->finalizer_func = finalizer_func;
	te->client_data = client_data;
	te->next = ev_loop->time_event_head;
	ev_loop->time_event_head = te;
	return id;
}

int ae_delete_time_event(ae_event_loop * ev_loop, long long id)
{
	ae_time_event * te, *prev = NULL;
	te = ev_loop->time_event_head;
	while (te) {
		if (te->id == id) {
			if (prev == NULL)
				ev_loop->time_event_head = te->next;
			else
				prev->next = te->next;

			if (te->finalizer_func)
				te->finalizer_func(ev_loop, te->client_data);
			free(te);
			return 0;
		}
		prev = te;
		te = te->next;
	}

	return -1;
}

static ae_time_event * ae_search_nearest_timer(ae_event_loop * ev_loop)
{
	ae_time_event * te = ev_loop->time_event_head;
	ae_time_event * nearest = NULL;

	while (te) {
		if (!nearest || 
					te->when_sec < nearest->when_sec || 
					(te->when_sec == nearest->when_sec &&
					te->when_ms < nearest->when_ms))
			nearest = te;

		te = te->next;
	}
	return nearest;
}

static int process_time_event(ae_event_loop * ev_loop)
{
	int processed = 0;
	ae_time_event * te;
	long long maxid;
	time_t now = time(NULL);

	if (now < ev_loop->last_time) {
		te = ev_loop->time_event_head;
		while (te) {
			te->when_sec = 0;
			te = te->next;
		}
	}

	ev_loop->last_time = now;
	te = ev_loop->time_event_head;
	maxid = ev_loop->time_event_next_id - 1;
	while (te) {
		long now_sec, now_ms;
		long long id;

		if (te->id > maxid) {
			te = te->next;
			continue;
		}
		ae_get_time(&now_sec, &now_ms);
		if (now_sec > te->when_sec || 
				(now_sec == te->when_sec && now_ms >= te->when_ms))
		{
			int retval;
			
			id = te->id;
			retval = te->time_func(ev_loop, id, te->client_data);
			processed++;

			if (retval != AE_NOMORE) 
				ae_add_milliseconds_to_now(retval, &te->when_sec, &te->when_ms);
			else
				ae_delete_time_event(ev_loop, id);

			te = ev_loop->time_event_head;
		} else {
			te = te->next;
		}
	}

	return processed;
}

int ae_process_events(ae_event_loop * ev_loop, int flags)
{
	int processed = 0, numevents = 0;
	struct timeval * tvp = NULL;
	if (!(flags & AE_TIME_EVENTS) && !(flags & AE_FILE_EVENTS)) return 0;

	// There is some fd registered
	if (ev_loop->maxfd != -1 ||
		((flags & AE_TIME_EVENTS) && (flags & AE_DONT_WAIT))) {
		int j;
		ae_time_event * shortest = NULL;
		struct timeval tv, *tvp = NULL;


		if (flags & AE_TIME_EVENTS && !(flags & AE_DONT_WAIT))
			shortest = ae_search_nearest_timer(ev_loop);

		if (shortest) {
			long now_sec, now_ms;

			ae_get_time(&now_sec, &now_ms);
			tvp = &tv;
			tvp->tv_sec = shortest->when_sec - now_sec;
			if (shortest->when_ms < now_ms) {
							tvp->tv_usec = ((shortest->when_ms+1000) - now_ms)*1000;
							tvp->tv_sec --;
			} else {
							tvp->tv_usec = (shortest->when_ms - now_ms)*1000;
			}
			if (tvp->tv_sec < 0) tvp->tv_sec = 0;
			if (tvp->tv_usec < 0) tvp->tv_usec = 0;
		} else {
			if (flags & AE_DONT_WAIT) {
				tv.tv_sec = tv.tv_usec = 0;
				tvp = &tv;
			} else {
				tvp = NULL;
			}
		}

		numevents = ae_api_poll(ev_loop, tvp);
		for (j = 0; j < numevents; j++) {
			// Registered event
			ae_file_event * fe = &ev_loop->events[ev_loop->fired[j].fd];
			// Fired event
			int mask = ev_loop->fired[j].mask;
			int fd = ev_loop->fired[j].fd;
			int rfired = 0;
		
			if (fe != NULL && (fe->mask & mask & AE_READABLE)) {
				rfired = 1;
				fe->r_file_func(ev_loop, fd, fe->client_data, mask);
			}
			
			if (fe != NULL && (fe->mask & mask & AE_WRITABLE)) {
				if (!rfired || fe->w_file_func != fe->r_file_func)
					fe->w_file_func(ev_loop, fd, fe->client_data, mask);
			}

			processed++;
		}
	}

	if (flags & AE_TIME_EVENTS)
		processed += process_time_event(ev_loop);

	return processed;
}

int ae_wait(int fd, int mask, long long milliseconds)
{
	struct pollfd pfd;
	int retmask = 0, retval;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	
  if (mask & AE_READABLE) pfd.events |= POLLIN;
  if (mask & AE_WRITABLE) pfd.events |= POLLOUT;

  if ((retval = poll(&pfd, 1, milliseconds))== 1) {
    if (pfd.revents & POLLIN) retmask |= AE_READABLE;
    if (pfd.revents & POLLOUT) retmask |= AE_WRITABLE;
		if (pfd.revents & POLLERR) retmask |= AE_WRITABLE;
	  if (pfd.revents & POLLHUP) retmask |= AE_WRITABLE;
	  return retmask;
  } else {
    return retval;
  }
}

void ae_main(ae_event_loop * ev_loop)
{
	ev_loop->stop = 0;
	while (!ev_loop->stop) {
		ae_process_events(ev_loop, AE_ALL_EVENTS);
	}
}

char * ae_get_api_name(void)
{
	return ae_api_name();
}

void ae_set_before_sleep_func(ae_event_loop * ev_loop, ae_before_sleep_func * beforesleep)
{
	ev_loop->beforesleep = beforesleep;
}

