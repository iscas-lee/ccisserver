#include "ccis_thread.h"
#include "../log/ccis_log.h"
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

int	Create_Sync_Thread(void* function , void* args , Thread_Info** pt_list);	//创建同步处理线程，需要使用pthread_join保证退出
int	Create_ASync_Thread(void* function , void* args , Thread_Info** pt_list);	//创建异步处理线程，适用于无需返回值判断的功能
void	Destroy_ThreadList(Thread_Info** pt_list);		//销毁线程链表

int Create_Sync_Thread(void* function , void* args , Thread_Info** pt_list)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int retv	= 0;
	int init	= 0;
	Thread_Info* tmp	= NULL;
	Thread_Info* pos	= NULL;
	if (pt_list)
	{
		if (!(*pt_list))
		{
			(*pt_list)	= (Thread_Info*)calloc(1 , sizeof(Thread_Info));
			if (!*pt_list)
			{
				ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				return -1;
			}
			tmp	= *pt_list;
			init	= 1;
		}
		else
		{
			pos	= *pt_list;
			while (pos->next)
				pos	= pos->next;
			pos->next	= (Thread_Info*)calloc(1 , sizeof(Thread_Info));
			if (!pos->next)
			{
				ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				return -1;
			}
			tmp	= pos->next;
		}
		tmp->joinable	= true;
	}

	pthread_t thread_id;
	retv	=  pthread_create(&thread_id , NULL , function , args);
	if (pt_list && tmp)
	{
		if (!retv)
		{
			tmp->t_id	= thread_id;
			ccis_log_debug("线程%ld挂入..." , thread_id);
		}
		else
		{
			if (init)
			{
				free(*pt_list);
				*pt_list	= NULL;
			}
			else
			{
				free(tmp);
				pos->next	= NULL;	
			}
		}
	}

	return retv;
}

int Create_ASync_Thread(void* function , void* args , Thread_Info** pt_list)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	Thread_Info* tmp	= NULL;
	int retv	= 0;
	int init	= 0;
	Thread_Info* pos	= NULL;
	if (pt_list)
	{
		if (!(*pt_list))
		{
			*pt_list	= (Thread_Info*)calloc(1 , sizeof(Thread_Info));
			if (!(*pt_list))
			{
				ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				return -1;
			}
			tmp	= *pt_list;
			init	= 1;
		}
		else
		{
			pos	= *pt_list;
			while (pos->next)
				pos	= pos->next;
			pos->next	= (Thread_Info*)calloc(1 , sizeof(Thread_Info));
			if (!pos->next)
			{
				ccis_log_emerg("[%s:%d]内存分配失败：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
				return -1;
			}
			tmp	= pos->next;
		}
		tmp->joinable	= false;
	}

	pthread_t thread_id;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr , PTHREAD_CREATE_DETACHED);
	retv	= pthread_create(&thread_id , &attr , function , args);

	if (pt_list && tmp)
	{
		if (!retv)
		{
			tmp->t_id	= thread_id;
			ccis_log_debug("线程%ld挂入..." , thread_id);
		}
		else
		{
			if (init)
			{
				free(*pt_list);
				*pt_list	= NULL;
			}
			else
			{
				free(tmp);
				pos->next	= NULL;	
			}
		}
	}

	return retv;
}

void Destroy_ThreadList(Thread_Info** pt_list)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (!pt_list || !*pt_list)
		return ;

	Thread_Info* tmp	= NULL;
	while (*pt_list)
	{
		tmp	= *pt_list;
		if (tmp->joinable)
			pthread_join(tmp->t_id , NULL);
		else
			pthread_cancel(tmp->t_id);
		ccis_log_debug("线程%ld已退出..." , tmp->t_id);
		*pt_list	= (*pt_list)->next;
	}
	return ;
}
