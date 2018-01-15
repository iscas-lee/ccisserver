#include "ccis_epoll.h"
#include "../global_schedule.h"
#include <errno.h>
#include "../../log/ccis_log.h"

int	Create_Events_Pool();
int	Register_Events(Channel* ch);
int	Update_Events(Channel* ch);
int	Unregister_Events(Channel* ch);
int	Accept_Events(int timeout_ms);
void	Destroy_Events_Pool();

int Create_Events_Pool()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	memset(&stEPOLL , 0 , sizeof(_stEPOLL));
	stEPOLL.epollfd	= epoll_create1(EPOLL_CLOEXEC);
	if (stEPOLL.epollfd <= 0)
	{
		retv	= -1;
		ccis_log_emerg("Epoll Create Failed");
		goto clean_up;
	}
	
	stEPOLL.curfd	= 0;
	stEPOLL.maxfds	= MAX_EVENTS;

clean_up:	
	return retv;
}

int Register_Events(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	if (stEPOLL.curfd + 1 >= stEPOLL.maxfds)
	{
		ccis_log_alert("[ip:%s]Too many connections" , ch->r_ip);
		retv	= -1;
		goto clean_up;
	}
	
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;

	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_ADD , ch->fd , &ev);
	if (retv)
	{
		ccis_log_alert("[ip:%s]Register Event Failed , errno %d" , ch->r_ip , errno);
		goto clean_up;
	}

	stEPOLL.clients[stEPOLL.curfd].fd	= ch->fd;
	stEPOLL.clients[stEPOLL.curfd].events	= ch->events;
	strcpy(stEPOLL.clients[stEPOLL.curfd].r_ip , ch->r_ip);			//warning   貌似不需要保存？？？
	stEPOLL.curfd ++;

clean_up:
	return retv;
}

int Update_Events(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;
	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_MOD , ch->fd , &ev);
	return retv;
}

int Accept_Events(int timeout_ms)
{
	struct epoll_event activeEvs[MAX_EVENTS];
	int counts	= epoll_wait(stEPOLL.epollfd , activeEvs , MAX_EVENTS , timeout_ms);
	if (counts == -1)
	{
		ccis_log_err("epoll_wait error , error reason : %s" , strerror(errno));
		return -1;
	}

	for (int i = 0 ; i < counts ; i ++)
	{
		Channel* ch	= (Channel*)activeEvs[i].data.ptr;
		int events	= activeEvs[i].events;
		ccis_log_debug("fd %d 事件号：%d" , ch->fd , events);

		if (unlikely(events & EPOLLHUP))				//先判断是不是异常挂断，因为hup事件总是携带in事件一起来，如果这个判断放在后面就永远触发不了
		{
			Unexpected_Hup(ch);
		}
		else if (events & (EPOLLIN | EPOLLERR))
		{
			handleRead(ch);
		}
		else if (events & EPOLLOUT)
		{
			handleWrite(ch);
		}
		else
		{
			ccis_log_warning("[ip:%s]Unknow Events %d " , ch->r_ip , events);
			Unregister_Events(ch);
		}
	}

	return 0;
}

int Unregister_Events(Channel* ch)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!ch)
		return 1;
	if (ch->fd < 0)
	{
		ccis_log_info("[ip:%s]连接已被移除！" , ch->r_ip);
		return 0;
	}
	int retv	= 0;
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;

	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_DEL , ch->fd , &ev);
	if (retv < 0)
	{
		ccis_log_err("[ip:%s]Cannot Unregister Event! errno %d" , ch->r_ip , errno);
		goto clean_up;
	}

	stEPOLL.curfd --;
	
clean_up:
	if (ch->fd > -1)
		Free_Channel(ch);
	return retv;
}

void Destroy_Events_Pool()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	//TODO:回收EPOLL池中的资源，并且释放每一个活跃连接
	if (stEPOLL.epollfd > 0)
		close(stEPOLL.epollfd);
	for (int i = 0 ; i < stEPOLL.curfd ; i ++)
	{
		if (stEPOLL.clients[i].ssl)
		{
			SSL_shutdown(stEPOLL.clients[i].ssl);
			SSL_free(stEPOLL.clients[i].ssl);
			stEPOLL.clients[i].ssl	= NULL;
			stEPOLL.clients[i].sslConnected	= 0;
		}
		if (stEPOLL.clients[i].fd >= 0)
		{
			Close_Socket(stEPOLL.clients[i].fd);
			stEPOLL.clients[i].fd	= -1;
			stEPOLL.clients[i].tcpConnected	= 0;
		}
	}
}
