#ifndef _GNU_SOURCE	//for accept4
#define _GNU_SOURCE
#endif

#include "network.h"
#include "../schedule/epoll/ccis_epoll.h"
#include <errno.h>
#include "../log/ccis_log.h"

Channel* Channel_New();
int	Create_Socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock);	//创建套接字，并绑定、监听、设置阻塞模式
void	Close_Socket(int fd);												//关闭套接字
int	Set_NonBlock(int fd , int flag);										//设置阻塞模式
Channel*	Accept_Connection(int source_fd);									//接收接入请求
int	Set_ChannelSock(Channel* ch , int fd , int events);								//设置连接结构体的socket fd与events
int	Get_Remote_HostIP(int fd , char* ip , int ip_len);
void	Free_Channel(Channel* ch);
int	Connect_Server(const char* ip , int port , int nonblock);				//连接指定服务器地址

Channel* Channel_New()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	Channel* result	= (Channel*)calloc(1 , sizeof(Channel));
	if (unlikely(!result))
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}
	return result;
}

int Create_Socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ip)
		return -1;
	if (!domain)
		domain	= AF_INET;
	if (!type)
		type	= SOCK_STREAM | SOCK_CLOEXEC;
	if (!proto)
		proto	= IPPROTO_TCP;
	if (!backlog)
		backlog	= 20;
	int sock_fd	= socket(domain , type , proto);
	if (sock_fd < 0)
		return -1;
	
	Set_NonBlock(sock_fd , nonblock);

	struct sockaddr_in stSockAddr;
	memset(&stSockAddr , 0 , sizeof(struct sockaddr_in));

	stSockAddr.sin_family	= domain;
	stSockAddr.sin_addr.s_addr	= inet_addr(ip);
	stSockAddr.sin_port	= htons(port);

	if (bind(sock_fd , (struct sockaddr *)&stSockAddr , sizeof(struct sockaddr_in)) == -1)
	{
		close(sock_fd);
		return -2;
	}

	if (listen(sock_fd , backlog) == -1)
	{
		close(sock_fd);
		return -3;
	}

	return sock_fd;
}

void Close_Socket(int fd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	shutdown(fd , SHUT_RDWR);
	close(fd);
}

int Set_NonBlock(int fd , int flag)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int prev	= fcntl(fd , F_GETFL);
	if (prev < 0)
		return errno;
	if (flag)
		return fcntl(fd , F_SETFL , prev | O_NONBLOCK);
	else
		return fcntl(fd , F_SETFL , prev & ~O_NONBLOCK);
}

Channel* Accept_Connection(int source_fd)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	Channel* result	= NULL;
	struct sockaddr_in raddr;
	socklen_t raddr_len	= sizeof(raddr);
	char r_ip[CCIS_IP_LEN];
	int cfd;
	int r_port;
	while ((cfd = accept4(source_fd , (struct sockaddr*)&raddr , &raddr_len , SOCK_CLOEXEC)) >= 0)
	{
		struct sockaddr_in peer;
		socklen_t alen	= sizeof(peer);
		int r	= getpeername(cfd , (struct sockaddr*)&peer , &alen);
		if (unlikely(r < 0))
		{
			continue;			//warning  直接继续是否会出现问题
		}
		inet_ntop(AF_INET , &raddr.sin_addr , r_ip , CCIS_IP_LEN);
		r_port	= ntohs(peer.sin_port);

		if (unlikely(stEPOLL.curfd >= MAX_EVENTS))
		{
			ccis_log_err("新连接接收失败：连接数已达上限");
			break;				//warning  连接数超过上线直接拒绝是否合适？
		}
		result	= Channel_New();
		if (!result)
		{
			ccis_log_err("新连接接收失败：连接结构体创建失败！");
			break;
		}
		sprintf(result->r_ip , "%s:%d" , r_ip , r_port);
		Set_NonBlock(cfd , 1);			//warning  在此处设置非阻塞是否合适？
		Set_ChannelSock(result , cfd , EPOLLIN | EPOLLOUT);
		ccis_log_notice("[ip:%s]Connection Accepted.." , result->r_ip);
	}

	return result;
}

int Set_ChannelSock(Channel* ch , int fd , int events)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ch)
		return 1;

	ch->fd		= fd;
	ch->events	= events;
	return 0;
}

int Get_Remote_HostIP(int fd , char* ip , int ip_len)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ip)
		return -1;
	struct sockaddr_in raddr;
	socklen_t raddr_len	= sizeof(raddr);
	int r	= getpeername(fd , (struct sockaddr*)&raddr , &raddr_len);
	if (!r)
	{
		inet_ntop(AF_INET , &raddr.sin_addr , ip , ip_len);
		return 0;
	}
	return 1;
}

void Free_Channel(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ch)
		return;

	if (ch->fd > -1)
	{
		Close_Socket(ch->fd);
		ch->fd	= -1;
		ch->tcpConnected = 0;
	}

	if (ch->ssl)
	{
		SSL_shutdown(ch->ssl);
		SSL_free(ch->ssl);
		ch->sslConnected = 0;
	}

	free(ch);
	ch	= NULL;
	return ;
}

int Connect_Server(const char* ip , int port , int nonblock)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ip)
		return -1;

	int socketfd	= socket(AF_INET , SOCK_STREAM , 0);
	if (socketfd < 0)
	{
		ccis_log_err("Socket创建失败：%s" , strerror(errno));
		goto clean_up;
	}
	struct sockaddr_in server_addr;
	memset(&server_addr , 0 , sizeof(server_addr));
	server_addr.sin_family	= AF_INET;
	server_addr.sin_port	= htons(port);
	inet_pton(AF_INET , ip , &server_addr.sin_addr);

	if (connect(socketfd , (struct sockaddr*)&server_addr , sizeof(server_addr)))
	{
		ccis_log_err("无法连接到服务器[%s:%d]：%s" , ip , port , strerror(errno));
		close(socketfd);
		socketfd	= -1;
		goto clean_up;
	}

	Set_NonBlock(socketfd , nonblock);
	ccis_log_debug("socket连接已建立");

clean_up:
	return socketfd;
}
