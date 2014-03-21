#include <sys/select.h>
#include <stdlib.h>
#include <string.h>

#include "ae.h"

typedef struct ae_api_state {
	fd_set rfds, wfds;
	fd_set _rfds, _wfds;
} ae_api_state;

static int ae_api_create(ae_event_loop * ev_loop)
{
	ae_api_state * state = (ae_api_state *)malloc(sizeof(ae_api_state));
	if (!state) return -1;
	FD_ZERO(&state->rfds);
	FD_ZERO(&state->wfds);

	FD_ZERO(&state->_rfds);
	FD_ZERO(&state->_wfds);
	ev_loop->api_data = state;

	return AE_OK;
}

static void ae_api_free(ae_event_loop * ev_loop)
{
	free(ev_loop->api_data);
}

static int ae_api_add_event(ae_event_loop * ev_loop, int fd, int mask)
{
	ae_api_state * state = ev_loop->api_data;

	if (mask & AE_READABLE) FD_SET(fd, &state->rfds);
	if (mask & AE_WRITABLE) FD_SET(fd, &state->wfds);
}

static void ae_api_del_event(ae_event_loop * ev_loop, int fd, int mask)
{
	ae_api_state * state = ev_loop->api_data;

	if (mask & AE_READABLE) FD_CLR(fd, &state->rfds);
	if (mask & AE_WRITABLE) FD_CLR(fd, &state->wfds);
}

static int ae_api_poll(ae_event_loop * ev_loop, struct timeval * tvp)
{
	ae_api_state * state = ev_loop->api_data;
	int retval, j, numevents = 0;

	memcpy(&state->_rfds, &state->rfds, sizeof(fd_set));
	memcpy(&state->_wfds, &state->wfds, sizeof(fd_set));

	retval = select(ev_loop->maxfd + 1, &state->_rfds,
									&state->_wfds, NULL, tvp);

	if (retval > 0) {
		for (j = 0; j <= ev_loop->maxfd; j++) {
			int mask = 0;
			ae_file_event * fe = &ev_loop->events[j];

			if (fe->mask == AE_NONE) continue;
			if (fe->mask & AE_READABLE && FD_ISSET(j, &state->_rfds))
				mask |= AE_READABLE;
			
			if (fe->mask & AE_WRITABLE && FD_ISSET(j, &state->_wfds))
				mask |= AE_WRITABLE;;

			ev_loop->fired[numevents].fd = j;
			ev_loop->fired[numevents].mask = mask;
			numevents++;
		}
	}
	FD_ZERO(&state->_rfds);
	FD_ZERO(&state->_wfds);
	return numevents;
}

static char * ae_api_name(void)
{
	return "select";
}
