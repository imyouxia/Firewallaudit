#ifndef __VIA_SSH2_H
#define __VIA_SSH2_H

#include <libssh2.h>
#include <libssh2_sftp.h>

typedef struct ssh2_dst_info {
	char * hostname;
	char * username;
	char * password;
	short    port;
} ssh2_dst_info;

typedef struct ssh2_conn {
	LIBSSH2_SESSION * session;
	int sockfd;
} ssh2_conn;

int ssh2_init_conn(ssh2_dst_info * info, ssh2_conn ** conn);
void destroy_ssh2_conn(ssh2_conn * conn);
#endif
