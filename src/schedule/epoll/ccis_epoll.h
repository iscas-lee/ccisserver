#ifndef __CCIS_EPOLL_H__
#define __CCIS_EPOLL_H__
#include "sys/epoll.h"
#include "../../network/network.h"

#define	MAX_EVENTS	10240

typedef struct{
	int epollfd;
	int curfd;
	int maxfds;
	Channel clients[MAX_EVENTS];
}_stEPOLL;

_stEPOLL	stEPOLL;

extern int	Create_Events_Pool();
extern int	Register_Events(Channel* ch);
extern int	Update_Events(Channel* ch);
extern int	Unregister_Events(Channel* ch);
extern int	Accept_Events(int timeout_ms);
extern void	Destroy_Events_Pool();


#endif
