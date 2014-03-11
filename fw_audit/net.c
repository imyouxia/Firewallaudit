#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "net.h"
#include "zlog.h"

extern zlog_category_t * logger;

// set sockfd or unixfd NONBLOCK
int net_socket_non_block(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		zlog_error(logger, "fcntl with F_GETFL failed");	
		return NET_ERR;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		zlog_error(logger, "fcntl with F_SETFL failed");	
		return NET_ERR;
	}

	return NET_OK;
}

// modify send buff size at kernel layer
// SOL_SOCKET表示socket层，SO_SNDBUF 设置送出的暂存区域
int net_set_send_buff(int fd, int buffsize)
{
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) == -1) {
		zlog_error(logger, "setsockopt for setting sending buff failed");	
		return NET_ERR;
	}

	return NET_OK;
}


// 定期确定连线是否已终止
int net_keep_alive(int fd, int interval)
{
	int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
		zlog_error(logger, "setsockopt for setting tcp keepalive failed");	
		return NET_ERR;
	}

#ifdef __linux__
	int val = interval;

	// IPPROTO_TCP 传输层 ，检查心跳	
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
		zlog_error(logger, "setsockopt for setting tcp keepidle failed");	
		return NET_ERR;
	}	

	val = interval / 3;
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
		zlog_error(logger, "setsockopt for setting tcp keepintvl failed");	
		return NET_ERR;
	}	

	val = 3;
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
		zlog_error(logger, "setsockopt for setting tcp keepcnt failed");	
		return NET_ERR;
	}	
#endif

	return NET_OK;
}

int net_tcp_keep_alive(int fd)
{
	int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
		zlog_error(logger, "setsockopt for setting tcp keepalive failed");	
		return NET_ERR;
	}

	return NET_OK;
}

static int net_set_tcp_no_delay(int fd, int val)
{
	// Nagle算法，就是有数据立马发出，Nagle是为了防止网络拥塞的。
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0) {
		zlog_error(logger, "setsockopt for setting tcp nodelay failed");	
		return NET_ERR;
	}	
	
	return NET_OK;
}

int net_enable_tcp_no_delay(int fd)
{
	return net_set_tcp_no_delay(fd, 1);
}

int net_disable_tcp_no_delay(int fd)
{
	return net_set_tcp_no_delay(fd, 0);
}

// create net socket
// domain my be AF_LOCAL, AF_INET or AF_INET6
// type may be SOCK_STREAM or SOCK_DGRAM
static int net_create_socket(int domain, int type)
{
	int s, retv, on = 1;
	if ((s = socket(domain, type, 0)) == -1) {
		zlog_error(logger, "create socket failed");	
		return NET_ERR;
	}

	if ((retv = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		zlog_error(logger, "setsockopt for setting SO_REUSEADDR failed");	
		return NET_ERR;
	}
	return s;
}


int net_resolve(const char * hostname, char * ipbuf)
{
	struct addrinfo hints;
	struct addrinfo * result, * iterator;

	// following four items must be set
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;

	// following four items can be just set to 0 or NULL
	hints.ai_addrlen = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	//getaddrinfo 是协议无关的，可以做出名字->地址，服务->端口的转换，返回一个指向addrinfo结构体链表的指针
	int retv = getaddrinfo(hostname, NULL, &hints, &result);
	if (retv != 0) {
		zlog_error(logger, "getaddrinfo with hostname: %s failed", hostname);	
		return NET_ERR;
	}

	for (iterator = result; iterator != NULL; iterator = iterator->ai_next) {
		// inet_ntop 将整数变为点分十进制
		inet_ntop(iterator->ai_family, &iterator->ai_addr, ipbuf, IPV4_ADDR_LENGTH);
		break;
	}

	return NET_OK;
}


static int net_tcp_generic_connect(const char * addr, int port, int flags)
{
	int retv, sockfd;
	struct sockaddr_in dst_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);

	if ((sockfd = net_create_socket(AF_INET, SOCK_STREAM)) == NET_ERR) {
		zlog_error(logger, "create TCP on IPV4 socket failed");	
		return NET_ERR;
	}

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(port);

	// Detect whether need to resolve addr
	// 将点分十进制变为整数
	if ((retv = inet_pton(AF_INET, addr, &dst_addr.sin_addr)) <= 0) {
		struct hostent * he;
		// 主机名到地址解析
		he = gethostbyname(addr);
		if (he == NULL) {
			zlog_error(logger, "resolve %s failed", addr);	
			return NET_ERR;
		}
		memcpy(&dst_addr.sin_addr, he->h_addr, sizeof(struct in_addr));
	}

	if (flags & NET_CONNECT_NONBLOCK) {
		if (net_socket_non_block(sockfd) == NET_ERR) {
			zlog_error(logger, "set socket unblock failed");
			return NET_ERR;
		}
	}

	retv = connect(sockfd, (struct sockaddr *)&dst_addr, addr_len);
	if (retv == -1) {
		if (errno == EINPROGRESS && (flags & NET_CONNECT_NONBLOCK)) {
			return sockfd;
		}

		zlog_fatal(logger, "connect %s:%d failed", addr, port);
		close(sockfd);
		return NET_ERR;
	}

	return sockfd;
}

int net_tcp_connect(const char * addr, int port)
{
	return net_tcp_generic_connect(addr, port, NET_CONNECT_NONE);
}


int net_tcp_nonblock_connect(const char * addr, int port)
{
	return net_tcp_generic_connect(addr, port, NET_CONNECT_NONBLOCK);
}

static int net_unix_generic_connect(const char * path, int flags)
{
	int unixfd;
	int retv;
	// 一种进程间通信IPC，Unix Doamin Socket.
	struct sockaddr_un dst_addr;

	unixfd = net_create_socket(AF_LOCAL, SOCK_STREAM);
	if (unixfd == NET_ERR) {
		// LOG
		return NET_ERR;
	}

	dst_addr.sun_family = AF_LOCAL;
	strncpy(dst_addr.sun_path, path, sizeof(dst_addr.sun_path) - 1);

	if (flags & NET_CONNECT_NONBLOCK) {
		if (net_socket_non_block(unixfd) == NET_ERR) {
			zlog_error(logger, "set socket unblock failed");
			return NET_ERR;
		}
	}

	// Whether to remove already existed path
	retv = connect(unixfd, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	if (retv == -1) {
		// 当以非阻塞的方式进行连接的时候，返回-1并不一定表示错误，如果错误码为EINPROGRESS，表示链接还在进行中 
		if (errno == EINPROGRESS && (flags & NET_CONNECT_NONBLOCK)) {
			return unixfd;
		}

		zlog_fatal(logger, "connect path:%s failed", path);
		close(unixfd);
		return NET_ERR;
	}

	return unixfd;
}

int net_unix_connect(const char * addr, int port)
{
	return net_unix_generic_connect(addr, NET_CONNECT_NONE);
}

int net_unix_nonblock_connect(const char * addr, int port)
{
	return net_unix_generic_connect(addr, NET_CONNECT_NONBLOCK);
}

int net_read(int fd, char * buf, int count)
{
	int nread, totlen = 0;
	while (totlen != count) {
		nread = read(fd, buf, count - totlen);
		if (nread == 0) return totlen;
		if (nread == -1) {
			zlog_error(logger, "read on socket:%d failed", fd);
			return -1;
		}
		totlen += nread;
		buf += nread;
	}

	return totlen;
}


int net_write(int fd, char * buf, int count)
{
	int nwritten, totlen = 0;
	while (totlen != count) {
		nwritten = write(fd, buf, count - totlen);
		if (nwritten == 0) return totlen;
		if (nwritten == -1) {
			zlog_error(logger, "write on socket:%d failed", fd);
			return -1;
		}
		totlen += nwritten;
		buf += nwritten;
	}

	return totlen;
}

int net_listen(int fd, struct sockaddr * sa, socklen_t len)
{
	if (bind(fd, sa, len) == -1) {
		zlog_fatal(logger, "bind socket:%d with addr failed", fd);
		close(fd);
		return NET_ERR;
	}

	int retv;
	if ((retv = listen(fd, 511)) == -1) {
		zlog_fatal(logger, "listen on socket:%d failed", fd);
		close(fd);
		return NET_ERR;
	} 
	return NET_OK;
}

int net_tcp_server(const int port, const char * bindaddr)
{
	int sockfd;
	socklen_t addr_len;
	struct sockaddr_in src_addr;
	addr_len = sizeof(struct sockaddr_in);

	if ((sockfd = net_create_socket(AF_INET, SOCK_STREAM)) == NET_ERR) {
		return NET_ERR;
	}

	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons(port);
	src_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bindaddr &&  
				(inet_pton(AF_INET, bindaddr, (void *)&src_addr.sin_addr)) != 1) {
		return NET_ERR;
	}

	if ((net_listen(sockfd, (struct sockaddr *)&src_addr, addr_len)) == NET_ERR) {
		return NET_ERR;
	}

	return sockfd;
}

int net_unix_server(const char * path, mode_t perm)
{
	int unixfd;
	socklen_t addr_len;
	struct sockaddr_un src_addr;
	addr_len = sizeof(struct sockaddr_un);

	if ((unixfd = net_create_socket(AF_LOCAL, SOCK_STREAM)) == NET_ERR) {
		return NET_ERR;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.sun_family = AF_LOCAL;
	strncpy(src_addr.sun_path, path, sizeof(src_addr.sun_path) - 1);
	if ((net_listen(unixfd, (struct sockaddr *)&src_addr, addr_len)) == NET_ERR) {
		return NET_ERR;
	}
	
	if (perm)
		chmod(src_addr.sun_path, perm);

	return unixfd;;
}

static int net_generic_accept(int s, struct sockaddr * sa, socklen_t * len)
{
	int fd;
	while (1) {
		fd = accept(s, sa, len);
		if (fd == -1) {
			// 由于信号中断，产生的错误
			if (errno == EINTR)
				continue;
			else {
				return NET_ERR;
			}
		}
		break;
	}

	return fd;
}

int net_tcp_accept(int s, char * ip, int * port)
{
	int fd;
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);

	if ((fd = net_generic_accept(s, (struct sockaddr *)&sa, &salen)) == NET_ERR) {
		return NET_ERR;
	}

	if (ip)
		inet_ntop(AF_INET, (void *)&sa.sin_addr, ip, IPV4_ADDR_LENGTH);

	if (port)
		*port = ntohs(sa.sin_port);	
	
	return fd;
}

int net_unix_accept(int s)
{
	int fd;
	struct sockaddr_un sa;
	socklen_t salen = sizeof(sa);

	if ((fd = net_generic_accept(fd, (struct sockaddr *)&sa, &salen)) == NET_ERR) {
		return NET_ERR;
	}

	return fd;
}


int net_peer_to_string(int fd, char * ip, int * port)
{
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);

	if (getpeername(fd, (struct sockaddr *)&sa, &salen) == -1) {
		*port = 0;
		ip[0] = '?';
		ip[1] = '?';

		return NET_ERR;
	}

	if (ip) inet_ntop(AF_INET, (void *)&sa.sin_addr, ip, IPV4_ADDR_LENGTH);
	if (port) *port = ntohs(sa.sin_port);

	return NET_OK;
}


int net_sock_name(int fd, char * ip, int * port)
{
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);

	if (getsockname(fd, (struct sockaddr *)&sa, &salen) == -1) {
		*port = 0;
		ip[0] = '?';
		ip[1] = '?';

		return NET_ERR;
	}

	if (ip) inet_ntop(AF_INET, (void *)&sa.sin_addr, ip, IPV4_ADDR_LENGTH);
	if (port) *port = ntohs(sa.sin_port);

	return NET_OK;
}

