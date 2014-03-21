#include <fcntl.h>
#include <sys/time.h>
#include <sys/signal.h>
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
#include <termios.h>
#include <malloc.h>

#include "net.h"
#include "zlog.h"
#include "telnet.h"
#include "inifile.h"
#include "constant.h"

static struct termios tntty;
static struct termios oldtty;
static char	t_flushc, t_intrc, t_quitc, sg_erase, sg_kill;

 zlog_category_t * logger;
 char * conf_buff;
char	synching;	/* non-zero, if we are doing telnet SYNCH	*/

/*------------------------------------------------------------------------
 *  * tcdm - handle the telnet "DATA MARK" command (marks end of SYNCH)
 *   *------------------------------------------------------------------------
 *    */
int
tcdm(FILE *sfp, FILE *tfp, int c)
{
	if (synching > 0)
		synching--;
	return 0;
}

/*------------------------------------------------------------------------
 *  * rcvurg - receive urgent data input (indicates a telnet SYNCH)
 *   *------------------------------------------------------------------------
 *    */
void rcvurg(int sig)
{
	synching++;
}


static int ttysetup(void)
{
	if (tcgetattr(0, &oldtty) < 0)	/* save original tty state	*/
		zlog_error(logger, "can't get tty modes: %s\n", strerror(errno));

	sg_erase = oldtty.c_cc[VERASE];
	sg_kill = oldtty.c_cc[VKILL];
	t_intrc = oldtty.c_cc[VINTR];
	t_quitc = oldtty.c_cc[VQUIT];
	t_flushc = oldtty.c_cc[VDISCARD];

	tntty = oldtty;		/* make a copy to change	*/

	/* disable some special characters */
	tntty.c_cc[VINTR] = _POSIX_VDISABLE;
	tntty.c_cc[VQUIT] = _POSIX_VDISABLE;
	tntty.c_cc[VSUSP] = _POSIX_VDISABLE;
#ifdef VDSUSP
	tntty.c_cc[VDSUSP] = _POSIX_VDISABLE;
#endif

	if (tcsetattr(0, TCSADRAIN, &tntty) < 0)
		zlog_error(logger, "can't set tty modes: %s\n", strerror(errno));
	return 0;
}

/*static char * get_cfg_name(char * localpath)
{
	char * ptr;
	char * cfg_name;
	ptr = strrchr(localpath,'/');
	cfg_name = ptr + 1;
	return cfg_name;
}*/

int telnet(telnet_dst_info * dst_info, char * cmd, char * cfg_name)
{
	unsigned char buff[40960];
	memset(buff, '\0', sizeof(buff));

	/* create sockfd between telnet client and server*/
	int sockfd;
	sockfd = net_tcp_connect(dst_info->hostname, dst_info->port);

	ttysetup();

	fd_set arfds, awfds, rfds, wfds;
	FD_ZERO(&arfds);
	FD_ZERO(&awfds);
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(sockfd, &arfds);
	FD_SET(0, &arfds);

	FILE * sfp;
	sfp = fdopen(sockfd, "w");

	int on = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_OOBINLINE, (char *)(&on), sizeof(on));

	char * local_ip;
	char cmd_full[128];	
	memset(cmd_full, '\0', sizeof(cmd_full));
	strcpy(cmd_full,cmd);

	char * delim = "&";
	char * temp_cmd;
	
	int nfds;
	
	nfds = getdtablesize();
	if (cfg_name != NULL)
	{
		read_profile_string("local_node","ip",&local_ip,"10.109.34.184",conf_buff);
		strcat(cmd_full," ");
		strcat(cmd_full,local_ip);
		strcat(cmd_full," ");
		strcat(cmd_full,cfg_name);
		strcat(cmd_full,"\n");
		zlog_info(logger,"cmd_full :%s", cmd_full);
	}
		
//	printf("%s\n",cmd_full);
	int nread;
	while(1) {
		memcpy(&rfds, &arfds, sizeof(rfds));
		memcpy(&wfds, &awfds, sizeof(rfds));

		if (select(nfds, &rfds, &wfds, NULL, NULL) < 0)
		{
			if (errno == EINTR)
			continue;
			zlog_error(logger, "select failed");
		}

		if (FD_ISSET(sockfd, &rfds))
		{
			nread = read(sockfd, buff, sizeof(buff));
			if (nread < 0)
			{
				zlog_error(logger, "socket read failed");
			} else {
				if (nread == 0)
				{
					printf("connection closed\n");
					if (tcsetattr(0, TCSADRAIN, &oldtty) < 0)
					zlog_info(logger, "tcsetattr: %s", strerror(errno));
					return OK;
				}
				else
				{
//				write(STDOUT_FILENO, buff, nread);
					zlog_info(logger,"%s",buff);
					if (strstr(buff, "Username:"))
					{
						write(sockfd, dst_info->username, strlen(dst_info->username));
						write(sockfd, "\n", strlen("\n"));
						sleep(1);
					}
					else if (strstr(buff,"Password:"))
					{
						write(sockfd, dst_info->password, strlen(dst_info->password));
						write(sockfd, "\n", strlen("\n"));
						sleep(1);
					}
					else if (strstr(buff,"username or password error"))
					{
						zlog_error(logger, "[telnet connect error]:username or password error");
						break;
					}
					else if (strstr(buff," Unknown command."))
					{
						zlog_error(logger, "[telnet connect error]: Unknown command");
						break;
					}
					else if (strstr(buff," Command incomplete."))
					{
						zlog_error(logger, "[telnet connect error]: Command incomplete");
						break;
					}
					else if (strstr(buff,"host>"))
					{
						write(sockfd, "enable\n", strlen("enable\n"));
						sleep(1);
					}
					else if (strstr(buff,"host#") && (cfg_name != NULL))
					{
						write(sockfd, cmd_full, strlen(cmd_full));
						sleep(1);
						//write(STDOUT_FILENO, cmd_full, strlen(cmd_full));
						write(sockfd, "exit\n", strlen("exit\n"));
						break;
					}
					else if (strstr(buff,"host#") && (cfg_name == NULL))
					{
						strtok(cmd_full, delim);
						//write(STDOUT_FILENO, cmd_full, strlen(cmd_full));
						write(sockfd, cmd_full, strlen(cmd_full));
						zlog_info(logger, "[auto_optimize_cmd]:%s", cmd_full);
						write(sockfd, "\n", strlen("\n"));
						sleep(1);
						while(temp_cmd = strtok(NULL, delim))
						{
						//	write(STDOUT_FILENO,temp_cmd,strlen(temp_cmd));
							write(sockfd, temp_cmd, strlen(temp_cmd));
							write(sockfd, "\n", strlen("\n"));
							sleep(1);
							zlog_info(logger, "[auto_optimize_cmd]:%s", temp_cmd);
						}
						write(sockfd, "exit\n", strlen("exit\n"));
						break;
					}
				}			
			}
		}
	}
	
	close(sockfd);
//	if(access("/home/fw_audit/fw_cfg/aa",0)==-1)
//	{
	//		mkdir("/home/fw_audit/fw_cfg/aa");
//	}
//	rename("/home/fw_audit/fw_cfg/tftpboot/con","/home/fw_audit/fw_cfg/aa/con");
	return OK;
}

#if 0
static int log_init(const char * conf)
{
	int rc;
	rc = zlog_init(conf);
	if (rc) {
		fprintf(stderr, "log init failed\n");	
		return FAIL;
	}
	logger = zlog_get_category("audit");
	if (!logger) {
		fprintf(stderr, "zlog_get_category failed\n");
		return FAIL;
	}
	return OK;
}

static int load_conf(const char * file)
{
  conf_buff = calloc(4096, sizeof(char));
  if (!conf_buff) {
    zlog_error(logger, "memory alloc failed");
    return FAIL;
  }

  int rc = load_ini_file(file, conf_buff);
  if (rc == FAIL) {
    free(conf_buff);
    zlog_error(logger, "load_ini_file failed");
    return FAIL;
  }
  return OK; 
}


int main(int argc, char * argv[])
{
	log_init("log.conf");
	load_conf("fw_audit.conf");
	telnet_dst_info dst_info;
	dst_info.hostname = "10.109.32.168";
	dst_info.port = 23;
	dst_info.username = "admin";
	dst_info.password = "venus.fw";

	telnet(&dst_info, "copy startup-config tftp", "conf123456");
  
	return 0;
}

#endif
