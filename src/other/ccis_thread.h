#ifndef __CCIS_THREAD_H__
#define __CCIS_THREAD_H__
#include <pthread.h>
#include <stdbool.h>

typedef struct _Thread_Info{
	pthread_t t_id;
	bool joinable;
	struct _Thread_Info* next;
}Thread_Info;

extern int	Create_Sync_Thread(void* function , void* args , Thread_Info** pt_list);
extern int	Create_ASync_Thread(void* function , void* args , Thread_Info** pt_list);

extern void	Destroy_ThreadList(Thread_Info** pt_list);

#endif
