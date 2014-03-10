#include <libssh2.h>
#include <libssh2_sftp.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>

#include "net.h"
#include "via_ssh2.h"
#include "libssh2_config.h"
#include "zlog.h"

//extern zlog_category_t * logger;
zlog_category_t * logger;
const char * keyfile1 = "~/.ssh/id_rsa.pub";
const char * keyfile2 = "~/.ssh/id_rsa";
static void fingerprint_ssh2_conn(ssh2_conn * conn);

static int waitsocket(ssh2_conn * conn)
{
	struct timeval timeout;
	int rc;
	fd_set fd;
	fd_set * writefd = NULL;
	fd_set * readfd = NULL;
	int dir;

	FD_ZERO(&fd);
	FD_SET(conn->sockfd, &fd);
	
	dir = libssh2_session_block_directions(conn->session);

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		readfd = &fd;

	if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
		writefd = &fd;

	rc = select(conn->sockfd + 1, readfd, writefd, NULL, &timeout);
	return rc;
}

static void close_channel(LIBSSH2_CHANNEL * channel)
{
	libssh2_channel_free(channel);
}


void destroy_ssh2_conn(ssh2_conn * conn)
{
	libssh2_session_disconnect(conn->session, "Normal shutdown, Thank you for playing");
	libssh2_session_free(conn->session);
	free(conn);

	close(conn->sockfd);
	libssh2_exit();
}


static void set_ssh2_session_block(LIBSSH2_SESSION * session, int flag)
{
	return libssh2_session_set_blocking(session, flag);
}


//第一步：根据目标地址信息，创建socket和session会话
static ssh2_conn * create_ssh2_conn(ssh2_dst_info * info)
{
	ssh2_conn * conn;
	conn = (ssh2_conn *)calloc(1, sizeof(ssh2_conn));
	if (!conn) {
		//LOG
		return NULL;
	}

	conn->sockfd = net_tcp_connect(info->hostname, info->port);
	if (conn->sockfd == -1) {
		//LOG
		free(conn);
		return NULL;
	}

	conn->session = libssh2_session_init();
	if (!conn->session) {
		// LOG
		free(conn);
		return NULL;
	}

	return conn;
}

//第二步：建立ssh通话句柄
static int set_up_ssh2_conn(ssh2_conn * conn)
{
	int rc;
//	set_ssh2_session_block(conn->session, 0);
	while ((rc = libssh2_session_handshake(conn->session, conn->sockfd)) == LIBSSH2_ERROR_EAGAIN)
		;
	
	if (rc == LIBSSH2_ERROR_SOCKET_NONE ) {
		zlog_error(logger, "libssh2_session_handshake failed");
		return -1;
	}

	return rc;
}

static LIBSSH2_KNOWNHOSTS * collect_known_hosts(ssh2_conn * conn)
{
	LIBSSH2_KNOWNHOSTS * nh = NULL;
	nh = libssh2_knownhost_init(conn->session);

	if (!nh) {
		zlog_error(logger, "libssh2_knownhost_init failed");
		return NULL;
	}

	libssh2_knownhost_readfile(nh, "known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	libssh2_knownhost_writefile(nh, "dumpfile", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

	return nh;
}

static int fetch_authentication(ssh2_conn * conn, ssh2_dst_info * info)
{
	int auth_pw = 0;
	char * userauthlist = NULL;
	
	userauthlist = libssh2_userauth_list(conn->session, info->username, strlen(info->username));
	if (userauthlist == NULL) {
		auth_pw = 1;
		return auth_pw;
	}
	zlog_info(logger, "Authentication motheds: %s", userauthlist);
	
	//用户名 + 密码
	if (strstr(userauthlist, "password") != NULL){
		auth_pw |= 1;
	}

	//键盘交互
	if (strstr(userauthlist, "keyboard-interactive") != NULL){
		auth_pw |= 2;
	}

	//使用文件
	if (strstr(userauthlist, "publickey") != NULL){
		auth_pw |= 4;
	}
	return auth_pw;
}

static void fingerprint_ssh2_conn(ssh2_conn * conn)
{
	const char * fingerprint;

	fingerprint = libssh2_hostkey_hash(conn->session, LIBSSH2_HOSTKEY_HASH_SHA1);

	int i;
	printf("Fingerprint: ");
	for (i = 0; i < 20; i++) {
		printf("%02x ", (unsigned char)fingerprint[i]);
	}
	printf("\n");
}

//第三步：选择某种鉴权方式：用户名密码、键盘交互、文件读取
static int authenticate_ssh2_conn(ssh2_conn * conn, ssh2_dst_info * info)
{
	//判断对端主机允许的认证方式
	int auth_pw = 0;
	auth_pw = fetch_authentication(conn, info);
	char * userauthlist = NULL;

  if (auth_pw & 1) {
      /* We could authenticate via info->password */ 
      if (libssh2_userauth_password(conn->session, info->username, info->password)) {

          zlog_error(logger, "\tAuthentication by password failed.");
          return -1;
      } else {
          zlog_error(logger, "\tAuthentication by password succeeded.");
      }
  } else if (auth_pw & 2) {
      /* Or via keyboard-interactive */ 
/*
      if (libssh2_userauth_keyboard_interactive(conn->session, info->username,

                                                &kbd_callback) ) {
          printf("\tAuthentication by keyboard-interactive failed!\n");
          return -1;
      } else {
          printf("\tAuthentication by keyboard-interactive succeeded.\n");
      }
*/
      zlog_error(logger, "\tAuthentication by keyboard-interactive failed!");
  } else if (auth_pw & 4) {
      /* Or by public key */ 
      if (libssh2_userauth_publickey_fromfile(conn->session, info->username, keyfile1,
                                              keyfile2, info->password)) {
          zlog_error(logger, "\tAuthentication by public key failed!");
          return -1;
      } else {
          zlog_error(logger, "\tAuthentication by public key succeeded.");
      }
  } else {
      zlog_error(logger, "No supported authentication methods found!");
      return -1;
  }

	return 0;
}

static LIBSSH2_CHANNEL * create_ssh2_cmd_channel(ssh2_conn * conn)
{
	LIBSSH2_CHANNEL * channel = NULL;
	while ((channel = libssh2_channel_open_session(conn->session)) == NULL
				&& 
				(libssh2_session_last_error(conn->session, NULL, NULL, 0)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(conn);	
	}

	if (channel == NULL) {
		//LOG
		return NULL;
	}

	return channel;
}

static LIBSSH2_CHANNEL * create_ssh2_scp_recv_channel(ssh2_conn * conn, 
			const char * scppath, struct stat * fileinfo)
{
	LIBSSH2_CHANNEL * channel = NULL;
	channel = libssh2_scp_recv(conn->session, scppath, fileinfo);
	if (!channel) {
		return NULL;
	}

	return channel;
}


static LIBSSH2_CHANNEL * create_ssh2_scp_send_channel(ssh2_conn * conn,
			const char * remote_path, const char * local_path)
{
	int mode;
	size_t size;
	struct stat fileinfo;
	LIBSSH2_CHANNEL * channel = NULL;

	stat(local_path, &fileinfo);
	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	size = fileinfo.st_size;
	channel = libssh2_scp_send(conn->session, remote_path, mode, size);
	
	return channel;
}

int scp_recv_file(ssh2_conn * conn, const char * remote_path, const char * local_path)
{
	int rc;
	LIBSSH2_CHANNEL * channel = NULL;
	FILE * fp = NULL;
	struct stat fileinfo;
	int got = 0;

	unlink(local_path);
	fp = fopen(local_path, "w+");
	if (fp == NULL) {
		zlog_error(logger, "fopen %s failed", local_path);
		return -1;
	}

	channel = create_ssh2_scp_recv_channel(conn, remote_path, &fileinfo);
	if (!channel) {
		zlog_error(logger, "create_ssh2_scp_recv_channel");
		return -1;
	}

	int nwritten;
	char mem[512];
	int amount = sizeof(mem);

	while (got < fileinfo.st_size) {
		memset(mem, '\0', sizeof(mem));

		if ((fileinfo.st_size - got) < amount) {
			amount = fileinfo.st_size - got;
		}

		rc = libssh2_channel_read(channel, mem, amount);

		if (rc > 0) {
			nwritten = fwrite(mem, sizeof(char), rc, fp);
			got += nwritten;
		} else if (rc <= 0) {
			break;
		}
	}

	fclose(fp);
	libssh2_channel_free(channel);

	return got;
}


int scp_send_file(ssh2_conn * conn, const char * remote_path, const char * locale_path)
{
	char buff[1024];
	size_t nread = 0, nwritten = 0;
	FILE * fsrc = NULL;
	struct stat fileinfo;
	LIBSSH2_CHANNEL * channel = NULL;
	channel = create_ssh2_scp_send_channel(conn, remote_path, locale_path);

	stat(locale_path, &fileinfo);

	if (!channel) {
		//LOG
		return -1;
	}

	fsrc = fopen(locale_path, "r");
	if (!fsrc) {
		//LOG
		return -1;
	}

	memset(buff, '\0', sizeof(buff));
	while((nread = fread(buff, sizeof(char), sizeof(buff), fsrc)) > 0) {
		nwritten += libssh2_channel_write(channel, buff, nread);
		nread = 0;
		memset(buff, '\0', sizeof(buff));
	}

	if (nwritten != fileinfo.st_size) {
		zlog_error(logger, "file send failed\n");
		return -1;
	}

	return 0;
}


int sftp_file(ssh2_conn * conn, const char * remote_path, const char * local_path)
{
		int rc;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    sftp_session = libssh2_sftp_init(conn->session);

 
    if (!sftp_session) {
        fprintf(stderr, "Unable to init SFTP session\n");
        return -1;
    }
 
    fprintf(stderr, "libssh2_sftp_open()!\n");

    /* Request a file via SFTP */ 
    sftp_handle =
        libssh2_sftp_open(sftp_session, remote_path, LIBSSH2_FXF_READ, 0);

    if (!sftp_handle) {
        fprintf(stderr, "Unable to open file with SFTP: %ld\n",
                libssh2_sftp_last_error(sftp_session));

        return -1;
    }
    fprintf(stderr, "libssh2_sftp_open() is done, now receive data!\n");

    do {
        char mem[1024];
 
        /* loop until we fail */ 

        rc = libssh2_sftp_read(sftp_handle, mem, sizeof(mem));

        if (rc > 0) {
            write(1, mem, rc);
        } else {
            break;
        }
    } while (1);
 
    libssh2_sftp_close(sftp_handle);
    libssh2_sftp_shutdown(sftp_session);
}


// 功能1：在远程主机上通过SSH协议执行命令，并把执行结果返回
char * cmd_exec(ssh2_conn * conn, LIBSSH2_CHANNEL * channel, char * cmdline)
{
	int rc = 0;
	char cmd[1024];
	memset(cmd, '\0', sizeof(cmd));
	fgets(cmd, sizeof(cmd), stdin);

	while ((rc = libssh2_channel_exec(channel, cmd)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(conn);
	}

	if (rc != 0) {
		//LOG
		return NULL;
	}

	char buff[2048];
	char * final = calloc(1, sizeof(char) * 10);
	int nstrcpy = 0;
	for (;;) {
		rc = 0;

		do {
			memset(buff, '\0', sizeof(buff));
			rc = libssh2_channel_read(channel, buff, sizeof(buff) - 1);
			buff[rc] = '\0';

			final = realloc(final, nstrcpy + strlen(buff) + 1);
			strncpy(final + nstrcpy, buff, strlen(buff));
			nstrcpy += strlen(buff);
			final[nstrcpy] = '\0';
		} while(rc > 0);

		if (rc == LIBSSH2_ERROR_EAGAIN) {
			waitsocket(conn);
		} else {
			break;
		}
	}

	int exitcode;
	while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN) {
		waitsocket(conn);
	}

	exitcode = libssh2_channel_get_exit_status(channel);
	return final;
}

struct termios _saved_tio;
int tio_saved = 0;

static int _raw_mode(void)
{
    int rc; 
    struct termios tio;

    rc = tcgetattr(fileno(stdout), &tio);
    if (rc != -1) {
      _saved_tio = tio;
      tio_saved = 1;
      cfmakeraw(&tio);
			tio.c_oflag |= ONLCR;
      rc = tcsetattr(fileno(stdin), TCSADRAIN, &tio);
    }   

    return rc;
}
 
static int _normal_mode(void)
{
    if (tio_saved)
        return tcsetattr(fileno(stdout), TCSADRAIN, &_saved_tio);

    return 0;
}


int auto_optimize_via_pseudoterm(ssh2_conn * conn, const char * cmdline)
{
	int flags;
	fd_set set;
	struct timeval timeval_out;
  timeval_out.tv_sec = 1;
  timeval_out.tv_usec = 0;

	char cmdbuff[1024];

	memset(cmdbuff, '\0', sizeof(cmdbuff));

	snprintf(cmdbuff, sizeof(cmdbuff), "%s\n", cmdline);

  if ((flags = fcntl(conn->sockfd, F_GETFL)) == -1) {
    zlog_error(logger, "fcntl with F_GETFL failed: %s", strerror(errno));
    return -1;
  }

  if (fcntl(conn->sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    zlog_error(logger, "fcntl with F_SETFL failed: %s", strerror(errno));
    return -1;
  }

	LIBSSH2_CHANNEL * channel =  libssh2_channel_open_session(conn->session);
	if (!channel) {
		zlog_error(logger, "create channel failed");
		return -1;
	}

	if (libssh2_channel_request_pty(channel, "xterm") != 0) {
	  zlog_error(logger, "Failed to request a pty");
	  return -1;
	}

//_raw_mode();

	/* Request a shell */ 
	if (libssh2_channel_shell(channel) != 0) {
	  zlog_error(logger, "Failed to open a shell");
	  return -1;
	}

	int  i = 0, j = 0, k = 0;
	int retv;
	int nread, nstrcpy = 0;
	char buff[40960];

	struct winsize w_size;  
	w_size.ws_col = 512;
	w_size.ws_row = 32;

	while(libssh2_channel_request_pty_size(channel, w_size.ws_col, w_size.ws_row) < 0)
		fprintf(stderr, "Again\n");

	char * buff_a;

  while (1) {
		i++;
    FD_ZERO(&set);
    FD_SET(conn->sockfd, &set);
  
    if((retv = select(conn->sockfd + 1, &set, NULL, NULL, &timeval_out)) > 0) {
			memset(buff, '\0', sizeof(buff));
			if (FD_ISSET(conn->sockfd, &set)) {

    	  if ((nread = libssh2_channel_read(channel, buff, sizeof(buff))) == LIBSSH2_ERROR_EAGAIN) {
					zlog_error(logger, "libssh2_channel_read BLOCK");
					break;
				}

				buff[nread] = '\0';
				zlog_debug(logger, "Read content %s", buff);
				break;
			}
		}

		if (i == 1)
	    libssh2_channel_write(channel, cmdbuff, strlen(cmdbuff));
  }

  if (channel != NULL) {
		close_channel(channel);
  }

//_normal_mode();
  return 0;
}


int cmd_exec_via_pseudoterm(ssh2_conn * conn, const char * cmdline, 
				const char * prompt, const char * localpath)
{
	int flags;
	fd_set set;
	FILE * fp;
	struct timeval timeval_out;
  timeval_out.tv_sec = 1;
  timeval_out.tv_usec = 0;

	char cmdbuff[1024];
	char prompt_buff[64];

	memset(cmdbuff, '\0', sizeof(cmdbuff));
	memset(prompt_buff, '\0', sizeof(prompt_buff));

	snprintf(cmdbuff, sizeof(cmdbuff), "%s\n", cmdline);
	snprintf(prompt_buff, sizeof(prompt_buff), "%s", prompt);

	if ((fp = fopen(localpath, "w+")) == NULL) {
    zlog_error(logger, "fopen %s failed: %s", localpath, strerror(errno));
		return -1;
	}

  if ((flags = fcntl(conn->sockfd, F_GETFL)) == -1) {
    zlog_error(logger, "fcntl with F_GETFL failed: %s", strerror(errno));
		fclose(fp);
    return -1;
  }

  if (fcntl(conn->sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    zlog_error(logger, "fcntl with F_SETFL failed: %s", strerror(errno));
		fclose(fp);
    return -1;
  }

	LIBSSH2_CHANNEL * channel =  libssh2_channel_open_session(conn->session);
	if (!channel) {
		zlog_error(logger, "create channel failed");
		fclose(fp);
		return -1;
	}

	if (libssh2_channel_request_pty(channel, "xterm") != 0) {
	  zlog_error(logger, "Failed to request a pty");
		fclose(fp);
	  return -1;
	}

//_raw_mode();

	/* Request a shell */ 
	if (libssh2_channel_shell(channel) != 0) {
	  zlog_error(logger, "Failed to open a shell");
		fclose(fp);
	  return -1;
	}

	char * final = calloc(1, sizeof(char) * 10);
	if (!final) {
	  zlog_error(logger, "memory allocated failed");
		fclose(fp);
		return -1;
	}

	int  i = 0, j = 0, k = 0;
	int retv;
	int nread, nstrcpy = 0;
	char buff[40960];

	struct winsize w_size;  
	w_size.ws_col = 512;
	w_size.ws_row = 32;

	while(libssh2_channel_request_pty_size(channel, w_size.ws_col, w_size.ws_row) < 0)
		fprintf(stderr, "Again\n");

	char * buff_a;

  while (1) {
		i++;
    FD_ZERO(&set);
    FD_SET(conn->sockfd, &set);

  
    if((retv = select(conn->sockfd + 1, &set, NULL, NULL, &timeval_out)) > 0) {
			memset(buff, '\0', sizeof(buff));
			if (FD_ISSET(conn->sockfd, &set)) {

    	  if ((nread = libssh2_channel_read(channel, buff, sizeof(buff))) == LIBSSH2_ERROR_EAGAIN) {
					zlog_error(logger, "libssh2_channel_read BLOCK");
					break;
				}

				buff[nread] = '\0';
				j++;
				if (j == 1 && (strstr(buff, prompt_buff)) != NULL) {
					zlog_debug(logger, "BBBBBBBBBBBBBB read [PROMPT]\n %s", buff);
				} else {
					final = realloc(final, nstrcpy + strlen(buff) + 1);
					strncpy(final + nstrcpy, buff, strlen(buff));
					nstrcpy += strlen(buff);
					final[nstrcpy] = '\0';
				}
				zlog_debug(logger, "Read content %d times with %d bytes this time and total %d bytes", j, nread, nstrcpy);
			}
		} else if (retv == 0) {
			k++;
			if (k > 5) {
				zlog_info(logger, " [TIMEOUT]");

				char * cutstr;
				cutstr = strstr(final, prompt);
				if (cutstr != NULL) {
					while (*(cutstr - 1) != '\n') {
						*(cutstr - 1) = '\0';
						cutstr = cutstr - 1;
					}
					*(cutstr - 1) = '\0';
				}
				final[strlen(final) - 1] = '\0';

				break;
			}
		}

		if (i == 1)
	    libssh2_channel_write(channel, cmdbuff, strlen(cmdbuff));
  }


  if (channel != NULL) {
		close_channel(channel);
  }

	if (strstr(final, cmdline))
		fprintf(fp, "%s", final + strlen(cmdline));
	else 
		fprintf(fp, "%s", final);

	fclose(fp);
	free(final);

//_normal_mode();
  return 0;
}

int ssh2_init_conn(ssh2_dst_info * info, ssh2_conn ** conn)
{
	int ret = 0;
	ssh2_conn * conn_local;

	conn_local = create_ssh2_conn(info);
	if (conn_local == NULL) {
		// LOG
		return -1;
	}

	ret = set_up_ssh2_conn(conn_local);
	if (ret == -1) {
		// LOG
		return -1;
	}

	fingerprint_ssh2_conn(conn_local);
	ret = authenticate_ssh2_conn(conn_local, info);
	if (ret == -1) {
		//LOG
		return -1;
	}

	*conn = conn_local;
	return 0;
}

#if 0
int main(int argc, char * argv[])
{
	int rc;
	rc = zlog_init("log.conf");
	if (rc) {
		fprintf(stderr, "log init failed\n");
		return -1;
	}

	logger = zlog_get_category("audit");
	if (!logger) {
		fprintf(stderr, "zlog_get_category failed\n");
		return -1;
	}

	ssh2_dst_info info;
	info.hostname = "10.109.34.184";
	info.username = "admin";
	info.password = "venus.fw";
	info.port = 22;

	rc = libssh2_init(0);
	if (rc != 0) {
		zlog_error(logger, "ssh2 init failed");
		return -1;
	}
	ssh2_conn * conn = NULL;
	conn = create_ssh2_conn(&info);

	if (!conn) {
		fprintf(stderr, "create conn failed\n");
		return -1;
	}


	if (set_up_ssh2_conn(conn) == -1) {
		fprintf(stderr, "set up conn failed\n");
		return -1;
	}

	fingerprint_ssh2_conn(conn);

	if (authenticate_ssh2_conn(conn, &info) == -1) {
		fprintf(stderr, "authenticate failed\n");
		return -1;
	}


//int ret = cmd_exec_via_pseudoterm(conn, "start", "host> ", "localfile");
//system telentd stop

/*
	LIBSSH2_CHANNEL * channel =  create_ssh2_cmd_channel(conn);
	if (!channel) {
		fprintf(stderr, "create channel failed\n");
		return -1;
	}

	char * final;
	final = cmd_exec(conn, channel, "ls -l");
	printf("%s", final);
*/

//	sftp_file(conn, argv[1], NULL);
//	scp_recv_file(conn, "/root/install.log", "/root/install.log");
//	scp_send_file(conn, "/root/123", argv[1]);


	destroy_ssh2_conn(conn);
	return 0;
}
#endif
