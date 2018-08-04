#ifndef _SERV_H_
#define _SERV_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/thread.h>

#define MAXBUFLEN 1024 //最大缓冲区长度
#define MAXSTRLEN 128  //用户名和密码最大长度
#define SESSLEN 16 //最大sess长度
#define MAXUSERNUM 100 //最大用户数量
#define DEBUG

/********
 * 用户链表结点,存储用户名,密码
 *******/
struct user_list
{
	char name[MAXSTRLEN];
	char passwd[MAXSTRLEN];
	struct user_list *next;
};
/********
 * 存储从文件读取的配置信息
 *******/
struct config_info
{
	int portoto;
	int portcr;
	int portfr;
	struct user_list *head;
};
/********
 * 存储已连接的用户信息
 *******/
struct login_user
{
	char name[MAXSTRLEN];
	char session[SESSLEN];
	evutil_socket_t fd;
	struct bufferevent *bev;
	int is_loged_in;
	struct login_user *prev;
	struct login_user *next;
};

extern int g_usernum; //用户个数
extern struct config_info *g_info; //配置文件结构体指针
extern struct login_user *g_login_user; //登录用户链表头
extern int g_IO_time_out;

/*enum
{
	SIGNUP = 0,
	LOGIN,
	TIME,
	MESSAGE,
	LOGOUT
}*/
void Perror(char *str);



int config_init(const char *path);

evutil_socket_t serv_init(int port, int listen_backlog);

void accept_cb(evutil_socket_t listenfd, short events, void *arg);

void buffer_read_cb(struct bufferevent *bev, void *arg);

void event_cb(struct bufferevent *bev, short events, void *arg);

void session_generate(char *str);

int login_confirm(char *name, char *passwd);

int login(struct bufferevent *bev, struct login_user *self);

int get_session(struct bufferevent *bev, char *session);

int get_remain(struct bufferevent *bev, int *nremain);

int get_msg(struct bufferevent *bev, int remain, char *buf);

int send_length(struct bufferevent *bev, int length);

int send_type(struct bufferevent *bev, int type, int status);
/*void login_error(struct bufferevent *bev, struct login_user *self);*/

#endif