#include "serv.h"

int get_session(struct bufferevent *bev, char *session)
{
	int nread;
	char *fptr, *tptr;
	char buf[19];
	nread = bufferevent_read(bev, buf, SESSLEN + 2);
	buf[nread] = '\0';

	fptr = memchr(buf, 0x02, nread);
	tptr = memchr(fptr, 0x03, nread);
	if (fptr == NULL || tptr == NULL)
	{
		fprintf(stderr, "read_error,line %d\n", __LINE__);
		evbuffer_drain(bufferevent_get_input(bev), 1024);

		return -1;
	}
	fptr++;
	strncpy(session, fptr, SESSLEN);
	session[SESSLEN] = '\0';
	return 1;
}

int get_remain(struct bufferevent *bev, int *nremain)
{
	unsigned char buf[7];
	int nread;
	nread = bufferevent_read(bev, buf, 6);
	buf[nread] = '\0';
	*nremain = buf[1] | buf[2] << 8 | buf[3] << 16 | buf[4] << 24;
	if (*nremain <= 0 || *nremain > MAXBUFLEN || buf[0] != '\2' || buf[5] != '\3' || nread != 6)
	{
		evbuffer_drain(bufferevent_get_input(bev), 1024);
		fprintf(stderr, "read remain error,, nread = %d, nremain = %d, %d %d %d %d\n", nread, *nremain, buf[1], buf[2], buf[3], buf[4]);

		return -1;
	}
	return 1;
}

int get_msg(struct bufferevent *bev, int nremain, char *buf)
{
	int nread;
	if (nremain > MAXBUFLEN)
	{
		return -1;
	}
	alarm(1);
	while (nremain > 0 && g_IO_time_out == 0)
	{
		nread = bufferevent_read(bev, buf, nremain);
		buf += nread;
		nremain -= nread;
	}
	alarm(0);
	g_IO_time_out = 0;
	if (nremain)
	{
		return -1;
	}
	return 1;
}

int send_length(struct bufferevent *bev, int length)
{
	unsigned char sendbuf[6];
	//sprintf(sendbuf, "\002\001\001\001\001\003");
    sendbuf[0] = '\002';
	sendbuf[1] = length & 0xff;
	sendbuf[2] = (length >> 8) & 0xff;
	sendbuf[3] = (length >> 16) & 0xff;
	sendbuf[4] = (length >> 24) & 0xff;
    sendbuf[5] = '\003';
	bufferevent_write(bev, sendbuf, 6);
	return 1;
}

int send_type(struct bufferevent *bev, int type, int status)
{
	char sendbuf[7];
	sprintf(sendbuf, "\002%d\003\002%d\003", type, status);
	bufferevent_write(bev, sendbuf, 6);
	return 1;
}