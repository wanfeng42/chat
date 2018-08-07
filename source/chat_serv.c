#include "serv.h"

int g_usernum;							//用户个数
struct config_info *g_info = NULL;		//配置文件结构体指针
struct login_user *g_login_user = NULL; //登录用户链表头
int g_IO_time_out;
thread_pool *pool; //线程池

inline void
Perror(char *str)
{
#ifdef DEBUG
	perror(str);
#endif
}

int config_init(const char *path)
{
	g_info = malloc(sizeof(struct config_info));
	char buf[MAXBUFLEN];
	FILE *configfp;
	struct user_list *head = NULL, *ptr;
	char *idx = 0; //接受find_sign函数返回的下标

	if ((configfp = fopen(path, "r")) == NULL)
	{
		Perror("init: can't open config file");
		exit(-1);
	}

	while (fgets(buf, MAXBUFLEN, configfp) != NULL)
	{
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';
		int temp;

		idx = memchr(buf, '=', strlen(buf));
		if (idx == NULL)
			continue;

		if (strncmp(buf, "portoto", idx - buf) == 0)
		{
			temp = atoi(idx + 1);
			if (temp > 1023 && temp < 65535)
				g_info->portoto = temp;
			else
				g_info->portoto = 49152;
		}
		else if (strncmp(buf, "portcr", idx - buf) == 0)
		{
			temp = atoi(idx + 1);
			if (temp > 1023 && temp < 65535 && temp != g_info->portoto)
				g_info->portcr = temp;
			else
				g_info->portcr = 49153;
		}
		else if (strncmp(buf, "portfr", idx - buf) == 0)
		{
			temp = atoi(idx + 1);
			if (temp > 1023 && temp < 65535 && temp != g_info->portoto && temp != g_info->portcr)
				g_info->portfr = temp;
			else
				g_info->portfr = 49154;
		}
		else if (strncmp(buf, "name", idx - buf) == 0)
		{
			if (g_usernum > MAXUSERNUM)
				break;
			ptr = (struct user_list *)malloc(sizeof(struct user_list));
			strcpy(ptr->name, idx + 1);
			fgets(buf, MAXBUFLEN, configfp);
			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = '\0';

			idx = memchr(buf, '=', strlen(buf));
			if (idx == NULL)
				strcpy(ptr->passwd, "");
			else
				strcpy(ptr->passwd, idx + 1);

			ptr->next = head;
			head = ptr;
			g_usernum++;
		}
	}
	g_info->head = head;
	fclose(configfp);
	return 0;
}

evutil_socket_t serv_init(int port, int listen_backlog)
{
	evutil_socket_t listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
	{
		Perror("socket error");
		return -1;
	}

	struct sockaddr_in servaddr;

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
	{
		Perror("bind error");
		return -1;
	}

	if (listen(listenfd, listen_backlog) == -1)
	{
		Perror("listen error");
		return -1;
	}

	evutil_make_socket_nonblocking(listenfd);
	evutil_make_listen_socket_reuseable(listenfd);

	return listenfd;
}

void accept_cb(evutil_socket_t listenfd, short events, void *arg)
{
	evutil_socket_t fd;

	struct sockaddr_in cliaddr;
	socklen_t clilen = sizeof(cliaddr);

	struct event_base *base = (struct event_base *)arg;

	fd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
	if (fd == -1)
	{
		Perror("accept error");
		return;
	}
	evutil_make_socket_nonblocking(fd);

	fprintf(stderr, "socket connected\n");

	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	struct login_user *p = malloc(sizeof(struct login_user));
	if (p == NULL)
	{
		Perror("malloc error");
		return;
	}

	p->fd = fd;
	p->bev = bev;
	p->is_loged_in = 0;
	p->next = g_login_user;
	p->prev = NULL;
	if (g_login_user != NULL)
		g_login_user->prev = p;
	g_login_user = p;

	bufferevent_setcb(bev, buffer_read_cb, NULL, event_cb, (void *)p);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

int login_confirm(char *name, char *passwd)
{
	struct user_list *head;
	head = g_info->head;
	while (head != NULL)
	{
		if ((strncmp(name, head->name, strlen(head->name))) == 0)
		{
			if ((strncmp(passwd, head->passwd, strlen(head->passwd))) == 0) //匹配
			{
				return 1;
			}
			return 0;
		}
		head = head->next;
	}
	return 0;
}

void session_generate(char *str)
{
	int n, c;
	int fd = open("/dev/urandom", O_RDONLY);

	n = 0;
	while (n < SESSLEN)
	{
		read(fd, &c, sizeof(int));
		str[n] = abs(c % 93) + '!';
		n++;
	}
	close(fd);
}

int login(struct bufferevent *bev, struct login_user *self)
{
	char buf[MAXBUFLEN];
	int nremain = 0;
	char *fptr, *tptr;

	char name[MAXSTRLEN];
	char passwd[MAXSTRLEN];

	//获取消息长度
	get_remain(bev, &nremain);

	//读取消息

	if (get_msg(bev, nremain, buf) == -1)
	{
		send_type(bev, 1, 0);
		fprintf(stderr, "get_msg error, line = %d\n", __LINE__);
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		return -1;
	}

	//从消息中找出name
	fptr = memchr(buf, 0x02, nremain);
	tptr = memchr(fptr, 0x03, nremain);
	if (fptr == NULL || tptr == NULL)
	{
		fprintf(stderr, "read_error,line %d\n", __LINE__);
		send_type(bev, 1, 0);
		return -1;
	}
	fptr++;
	strncpy(name, fptr, tptr - fptr);
	name[tptr - fptr] = '\0';

	//从消息中找出passwd
	fptr = memchr(tptr, 0x02, nremain);
	tptr = memchr(fptr, 0x03, nremain);
	if (fptr == NULL || tptr == NULL)
	{
		fprintf(stderr, "read_error,line %d\n", __LINE__);
		send_type(bev, 1, 0);
		return -1;
	}
	fptr++;
	strncpy(passwd, fptr, tptr - fptr);
	passwd[tptr - fptr] = '\0';

	if (login_confirm(name, passwd)) //登录认证成功
	{
		strncpy(self->name, name, strlen(name)); //存储用户name
		self->is_loged_in = 1;					 //设置已登录标记
		session_generate(self->session);		 //生成并存储session

		//向登录用户发送反馈。
		send_type(bev, 1, 1);
		sprintf(buf, "\002%s\003", self->session);
		bufferevent_write(bev, buf, SESSLEN + 2);
		fprintf(stderr, "login success , name = %s, session = %s\n", self->name, self->session);
	}
	else //登录认证失败
	{
		send_type(bev, 1, 0);
		fprintf(stderr, "login error , name = %s, passwd = %s\n", name, passwd);
		return -1;
	}
	return 1;
}

int send_time(struct bufferevent *bev, struct login_user *self)
{
	char buf[SESSLEN + 4];
	int nremain = 0;
	char *fptr, *tptr;

	//获取全部消息
	nremain = SESSLEN + 2;

	if (get_msg(bev, nremain, buf) == -1)
	{
		send_type(bev, 2, 0);
		fprintf(stderr, "get_msg error, line = %d\n", __LINE__);
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		return -1;
	}

	//从消息中找出session
	fptr = memchr(buf, 0x02, nremain);
	tptr = memchr(fptr, 0x03, nremain);
	if (fptr == NULL || tptr == NULL)
	{
		fprintf(stderr, "read_error,line %d\n", __LINE__);
		send_type(bev, 2, 0);
		return -1;
	}
	fptr++;

	if (strncmp(fptr, self->session, SESSLEN) == 0) //session认证成功
	{
		time_t ticks;
		char sendbuf[38]; //固定长度+24字节时间格式
		int len = 38 - 12;
		ticks = time(NULL);
		send_type(bev, 2, 1);
		send_length(bev, len);
		sprintf(sendbuf, "\002%.24s\003", ctime(&ticks));
		bufferevent_write(bev, sendbuf, len);
		fprintf(stderr, "send time success , time = %.24s, len = %d\n", ctime(&ticks), len);
	}
	else //session认证失败
	{
		fprintf(stderr, "TIME :wrong session, sess = %.16s, self sess = %.16s", fptr, self->session);
		send_type(bev, 2, 0);
	}
	return 1;
}

int send_msg_to_another_one(struct bufferevent *bev, struct login_user *self)
{
	char buf[MAXBUFLEN];
	int nread = 0;
	int nremain = 0;
	char *fptr, *tptr;
	//获取session
	if (get_session(bev, buf) == -1)
	{
		send_type(bev, 3, 0);
		return -1;
	}
	if (strncmp(buf, self->session, SESSLEN) == 0) //session认证成功
	{
		//获取消息长度
		if (get_remain(bev, &nremain) == -1)
		{
			send_type(bev, 3, 0);
			return -1;
		}
		//获取目标用户的name

		if (get_msg(bev, nremain, buf) == -1)
		{
			send_type(bev, 3, 0);
			fprintf(stderr, "get_msg error, line = %d\n", __LINE__);
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			return -1;
		}

		fptr = memchr(buf, 0x02, nremain);
		tptr = memchr(fptr, 0x03, nremain);
		if (fptr == NULL || tptr == NULL)
		{
			fprintf(stderr, "read_error,line %d\n", __LINE__);
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			send_type(bev, 3, 0);
			return -1;
		}
		fptr++;
		fprintf(stderr, "message to %.20s\n", fptr);

		//寻找登录用户中是否存在目标用户
		struct login_user *p = g_login_user;
		while (p)
		{
			if (strncmp(fptr, p->name, tptr - fptr) == 0 && p->is_loged_in == 1)
			{
				break;
			}
			p = p->next;
		}

		if (p) //找到了，将剩余消息转发。
		{
			//发送消息头
			send_type(p->bev, 3, 1);
			send_length(p->bev, nremain);
			bufferevent_write(p->bev, buf, nremain);

			get_remain(bev, &nremain);
			send_length(p->bev, nremain);

			while (nremain > 0)
			{
				nread = bufferevent_read(bev, buf, MAXBUFLEN);
				nremain -= nread;
				bufferevent_write(p->bev, buf, nread);
			}
		}
		else //没找到
		{
			fprintf(stderr, "user not found OR not online\n");
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			send_type(bev, 3, 0);
			return -1;
		}
	}
	else //session认证失败
	{
		fprintf(stderr, "MASSAGE: wrong session, sess = %.16s, self sess = %.16s\n", buf, self->session);
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		send_type(bev, 3, 0);
		return -1;
	}
	return 1;
}

int send_msg_to_chat_room(struct bufferevent *bev, struct login_user *self)
{
	char buf[MAXBUFLEN];
	int nread = 0;
	int nremain = 0;
	//获取session
	if (get_session(bev, buf) == -1)
	{
		send_type(bev, 4, 0);
		return -1;
	}
	if (strncmp(buf, self->session, SESSLEN) == 0) //session认证成功
	{
		//获取消息长度
		if (get_remain(bev, &nremain) == -1)
		{
			send_type(bev, 4, 0);
			return -1;
		}
		struct login_user *p = g_login_user;
		//发送消息头
		while (p)
		{
			send_type(p->bev, 4, 1);
			send_length(p->bev, nremain);
			p = p->next;
		}
		//发送剩余部分
		while (nremain > 0)
		{
			nread = bufferevent_read(bev, buf, MAXBUFLEN);
			nremain -= nread;
			p = g_login_user;
			while (p)
			{
				bufferevent_write(p->bev, buf, nread);
				p = p->next;
			}
			fprintf(stderr, "sent! nread = %d, nremain = %d", nread, nremain);
		}
	}
	return 1;
}

void *file_transfer(void *arg) //传给线程池的任务
{
	char buf[MAXBUFLEN];
	int nread = 0;
	int nremain = 0;
	char *fptr, *tptr;
	struct threadpool_arg *tparg = (struct threadpool_arg *)arg;
	struct bufferevent *bev = tparg->bev;
	struct login_user *self = tparg->self;
	//获取session
	if (get_session(bev, buf) == -1)
	{
		send_type(bev, 5, 0);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		free(tparg);
		return NULL;
	}
	if (strncmp(buf, self->session, SESSLEN) == 0) //session认证成功
	{
		//获取消息长度
		if (get_remain(bev, &nremain) == -1)
		{
			send_type(bev, 5, 0);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			free(tparg);
			return NULL;
		}
		//获取目标用户的name

		if (get_msg(bev, nremain, buf) == -1)
		{
			send_type(bev, 5, 0);
			fprintf(stderr, "get_msg error, line = %d\n", __LINE__);
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			free(tparg);
			return NULL;
		}

		fptr = memchr(buf, 0x02, nremain);
		tptr = memchr(fptr, 0x03, nremain);
		if (fptr == NULL || tptr == NULL)
		{
			fprintf(stderr, "read_error,line %d\n", __LINE__);
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			send_type(bev, 5, 0);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			free(tparg);
			return NULL;
		}
		fptr++;
		fprintf(stderr, "message to %s\n", fptr);

		//寻找登录用户中是否存在目标用户
		struct login_user *p = g_login_user;
		while (p)
		{
			if (strncmp(fptr, p->name, tptr - fptr) == 0 && p->is_loged_in == 1)
			{
				break;
			}
			p = p->next;
		}

		if (p) //找到了，将剩余消息转发。
		{
			//发送消息头
			send_type(p->bev, 5, 1);
			send_length(p->bev, nremain);
			bufferevent_write(p->bev, buf, nremain);

			if (get_remain(bev, &nremain) == -1)
			{
				send_type(bev, 5, 0);
				bufferevent_enable(bev, EV_READ | EV_WRITE);
				free(tparg);
				return NULL;
			}
			if (get_msg(bev, nremain, buf) == -1)
			{
				send_type(bev, 5, 0);
				fprintf(stderr, "get_msg error, line = %d\n", __LINE__);
				evbuffer_drain(bufferevent_get_input(bev), 1024);
				bufferevent_enable(bev, EV_READ | EV_WRITE);
				free(tparg);
				return NULL;
			}

			send_length(p->bev, nremain);
			bufferevent_write(p->bev, buf, nremain);

			get_remain(bev, &nremain);
			send_length(p->bev, nremain);

			while (nremain > 0)
			{
				nread = bufferevent_read(bev, buf, MAXBUFLEN);
				nremain -= nread;
				bufferevent_write(p->bev, buf, nread);
			}
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			free(tparg);
		}
		else //没找到
		{
			fprintf(stderr, "user not found OR not online\n");
			evbuffer_drain(bufferevent_get_input(bev), 1024);
			send_type(bev, 5, 0);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			free(tparg);
			return NULL;
		}
	}
	else //session认证失败
	{
		fprintf(stderr, "MASSAGE: wrong session, sess = %.16s, self sess = %.16s\n", buf, self->session);
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		send_type(bev, 5, 0);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		free(tparg);
		return NULL;
	}

	return NULL;
}

int sign_up(struct bufferevent *bev, struct login_user *self)
{
	//
	return 1;
}

void buffer_read_cb(struct bufferevent *bev, void *arg)
{

	char buf[10];
	int nread = 0;
	struct login_user *self = (struct login_user *)arg;

	nread = bufferevent_read(bev, buf, 3);
	if (nread != 3 || buf[0] != 0x02 || buf[2] != 0x03)
	{
		fprintf(stderr, "read_error,buf[0]=%x,buf[1]=%x,buf[2]=%x, nread = %d\n", buf[0], buf[1], buf[2], nread);
		bufferevent_write(bev, "\002\060\003", 3);
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		return;
	}

	if (buf[1] == '0')
	{
	}
	else if (buf[1] == '1') //登录
	{
		login(bev, self);
	}
	else if (buf[1] == '2') //获取时间
	{
		send_time(bev, self);
	}
	else if (buf[1] == '3') //消息转发
	{
		send_msg_to_another_one(bev, self);
	}
	else if (buf[1] == '4') //公共消息转发
	{
		send_msg_to_chat_room(bev, self);
	}
	else if (buf[1] == '5') //文件传输
	{
		bufferevent_disable(bev, EV_READ | EV_WRITE);
		struct threadpool_arg *thrarg = malloc(sizeof(struct threadpool_arg));
		thrarg->bev = bev;
		thrarg->self = self;
		add_task(pool, file_transfer, thrarg);
	}
}

void event_cb(struct bufferevent *bev, short events, void *arg)
{
	if (events & BEV_EVENT_EOF)
	{
		//do something on socket closed
		fprintf(stderr, "socket closed\n");
	}
	if (events & BEV_EVENT_ERROR)
	{
		//do something on socket error happened
		fprintf(stderr, "socket error\n");
	}
	struct login_user *self = (struct login_user *)arg;
	if (self == g_login_user)
	{
		g_login_user = g_login_user->next;
		free(self);
	}
	else
	{
		self->prev->next = self->next;
		free(self);
	}
	bufferevent_free(bev);
}

void IO_sig_alrm(int signo)
{
	g_IO_time_out = 1;
}

int run()
{
	struct event_base *base = event_base_new();
	evutil_socket_t listenfd = serv_init(g_info->portoto, 16);
	if (listenfd == -1)
	{
		return -1;
	}

	signal(SIGALRM, IO_sig_alrm);
	g_IO_time_out = 0;

	struct event *ev = event_new(base, listenfd, EV_READ | EV_PERSIST, accept_cb, (void *)base);
	event_add(ev, NULL);

	event_base_dispatch(base);
	event_base_free(base);

	return 0;
}

int main()
{
	config_init("./config");
	evthread_use_pthreads();
	/*printf("portoto = %d\nportcr = %d\nportfr = %d\n", g_info->portoto, g_info->portcr, g_info->portfr);
	struct user_list *p = g_info->head;
	while (p)
	{
		printf("name = %s\npasswd = %s\n", p->name, p->passwd);
		p = p->next;
	}*/
	pool = malloc(sizeof(thread_pool));
	init_pool(pool, 17);
	run();
	return 0;
}