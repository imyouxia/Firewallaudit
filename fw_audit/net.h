#ifndef __NET_H
#define __NET_H

#define NET_ERR -1
#define NET_OK	0

#define NET_CONNECT_NONE				0
#define NET_CONNECT_NONBLOCK		1

#define IPV4_ADDR_LENGTH				16
//#define IPV6_ADDR_LENGTH				128


int net_tcp_connect(const char * addr, int port);
int net_tcp_nonblock_connect(const char * addr, int port);
int net_unix_connect(const char * addr, int port);
int net_unix_nonblock_connect(const char * addr, int port);
int net_read(int fd, char * buf, int count);
int net_write(int fd, char * buf, int count);
int net_resolve(const char * hostname, char * ipbuf);
int net_tcp_server(const int port, const char * bindaddr);
int net_unix_server(const char * path, mode_t perm);
int net_tcp_accept(int s, char * ip, int * port);
int net_unix_accept(int s);
int net_socket_non_block(int fd);
int net_enable_tcp_no_delay(int fd);
int net_disable_tcp_no_delay(int fd);
int net_keep_alive(int fd, int interval);
int net_tcp_keep_alive(int fd);
int net_peer_to_string(int fd, char * ip, int * port);
int net_sock_name(int fd, char * ip, int * port);

#endif
