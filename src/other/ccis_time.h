#ifndef __CCIS_TIME_H__
#define __CCIS_TIME_H__

#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif
#include "time.h"
#include "sys/timeb.h"

#define SECOND_TIME_LEN	20

extern char*	Get_Localtime();
extern int	Get_Localyear();
extern char*	Get_Localdate();
extern long long Get_Systemtime_MS();					//征信使用的获取本地时间
extern double	Compute_PassSecond(time_t start , time_t end);		//计算时间差
extern int	Set_Alarm();						//设置闹钟
extern void	Show_Localtime();					//显示本地时间
extern int	Get_Remotetime(const char* addr);			//与时间服务器对时
extern time_t	Get_Time_From_String(char* timestr);			//字符串转time_t
extern char*	Get_String_From_Time(time_t* pstTime);			//time_t转字符串
extern char*	Compute_Days_Before(int days);				//计算X天前的日期

#endif
