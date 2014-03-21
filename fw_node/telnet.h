#ifndef __TELNET_H
#define __TELNET_H

typedef struct telnet_dst_info {
	char * hostname;
	int port;
	char * username;
	char * password;
} telnet_dst_info;

int telnet(telnet_dst_info * dst_info, char * cmd, char * cfg_name);
#endif
