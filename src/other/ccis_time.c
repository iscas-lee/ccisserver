#include "ccis_time.h"
#include "../ccis.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"
#include "../log/ccis_log.h"
#include <curl/curl.h>
#include <errno.h>

char*	Get_Localtime();
char*	Get_Localdate();
int	Get_Localyear();
long long Get_Systemtime_MS();
double	Compute_PassSecond(time_t start , time_t end);
int	Set_Alarm();
int	Set_Localtime(char* remotetime);
void	Show_Localtime();
static size_t header_callback(char* buffer , size_t size , size_t nitems , void* userdata);
int	Get_Remotetime(const char* addr);
time_t	Get_Time_From_String(char* timestr);
char*	Get_String_From_Time(time_t* pstTime);
char*	Compute_Days_Before(int days);

char* Get_Localtime()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	time_t tmpcal_ptr = {0};
	struct tm *tmp_ptr = NULL;

	tmpcal_ptr = time(NULL);
	
	tmp_ptr = localtime(&tmpcal_ptr);
	char *result = malloc(SECOND_TIME_LEN);
	if (result == NULL)        //0726 patch
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}
	sprintf(result, "%04d/%02d/%02d %02d:%02d:%02d", 1900 + tmp_ptr->tm_year, 1 + tmp_ptr->tm_mon, tmp_ptr->tm_mday,
        	tmp_ptr->tm_hour, tmp_ptr->tm_min, tmp_ptr->tm_sec);
	return result;
}

char* Get_Localdate()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	time_t tmpcal_ptr = {0};
	struct tm *tmp_ptr = NULL;

	tmpcal_ptr = time(NULL);
	
	tmp_ptr = localtime(&tmpcal_ptr);
	char *result = malloc(SECOND_TIME_LEN);
	if (result == NULL)        //0726 patch
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}
	sprintf(result, "%04d/%02d/%02d", 1900 + tmp_ptr->tm_year, 1 + tmp_ptr->tm_mon, tmp_ptr->tm_mday);
	return result;
}

int Get_Localyear()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	time_t tmpcal_ptr	= {0};
	struct tm* tmp_ptr	= NULL;

	tmpcal_ptr	= time(NULL);
	tmp_ptr		= localtime(&tmpcal_ptr);

	int result	= 0;
	result	= tmp_ptr->tm_year + 1900;

	return result;
}

double Compute_PassSecond(time_t start , time_t end)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	return difftime(end , start);
}

long long Get_Systemtime_MS()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct timeb stTimeb;
	ftime(&stTimeb);
	return 1000*stTimeb.time + stTimeb.millitm;
}

int Set_Alarm()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	int alarm_hour	= self_check_time;
	int alarm_min	= 59;
	int alarm_sec	= 60;

	unsigned int wait_time	= 0;

	time_t timep;
	struct tm *p = NULL;
	time(&timep);
	p = localtime(&timep);
	if (alarm_hour >= 7 && alarm_hour <= 18)
	{
	    ccis_log_warning("*****************************************WARNING**************************************");
	    ccis_log_warning("自检时间可能处于工作时间段(%d:00:00)！" , self_check_time);
	    ccis_log_warning("**************************************************************************************");
	}
	if (alarm_hour == 0)
	    alarm_hour = 24;
	if (alarm_hour - 1 >= p->tm_hour)            //已知BUG：例如在22:59:59设定，设定自检时间为23:00:00，那么可能会导致设置失败
	{
		wait_time += (alarm_sec - p->tm_sec) + 60 * (alarm_min - p->tm_min) + 60 * 60 * (alarm_hour - 1 - p->tm_hour);
	}
	else
	{
		wait_time += (alarm_sec - p->tm_sec) + 60 * (alarm_min - p->tm_min) + 60 * 60 * (23 - p->tm_hour + alarm_hour);
	}
	alarm(wait_time);
	ccis_log_info("设置%us之后自检", wait_time);
	int alarm_year = p->tm_year + 1900;
	int alarm_mon = p->tm_mon + 1;
	int alarm_day = p->tm_mday;
	if (alarm_hour - 1 >= p->tm_hour)    //当天
	{
	}
	else                    //次日
	{
		int rn = 0;
		if ((alarm_year % 4 == 0 && alarm_year % 100 != 0) || alarm_year % 400 == 0)        //闰年
				rn = 1;
    		if (alarm_mon == 1 || alarm_mon == 3 || alarm_mon == 5 || alarm_mon == 7 || alarm_mon == 8 || alarm_mon == 10 ||alarm_mon == 12)
		{
			if (alarm_day + 1 > 31)
			{
				alarm_day = 1;
				if (alarm_mon + 1 > 12)
				{
					alarm_mon = 1;
					alarm_year += 1;
				}
				else
					alarm_mon += 1;
        		}
        		else
            			alarm_day += 1;
    		}
    		else if (alarm_mon == 2)
		{
            		if (alarm_day + 1 > 28 + rn)
			{
                		alarm_mon = 3;
                		alarm_day = 1;
            		}
            		else
                		alarm_day += 1;
		}
		else
		{
			if (alarm_day + 1 > 30)
			{
            			alarm_day = 1;
            			alarm_mon += 1;
        		}
        		else
            			alarm_day += 1;
    		}
	}
	//LOGGER(2, "sys", "下次自检时间：%04d-%02d-%02d %02d:00:00", alarm_year, alarm_mon, alarm_day, alarm_hour);
	return 0;
}

int Set_Localtime(char* remotetime)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct tm stTime;
	struct timeval tv;
	time_t timet;

	memset(&stTime , 0 , sizeof(struct tm));
	strptime(remotetime , "%a, %d %b %Y %H:%M:%S" , &stTime);

	stTime.tm_hour += 8;

	timet	= mktime(&stTime);
	tv.tv_sec	= timet;
	tv.tv_usec	= 0;

	if (settimeofday(&tv , (struct timezone *) 0) < 0)
	{
		ccis_log_err("[%s] 设置时间失败！" , __FUNCTION__);
		return 1;
	}
	else
	{
		if (remotetime[strlen(remotetime) - 1] == '\n')
			remotetime[strlen(remotetime) - 1] = '\0';
		ccis_log_info("本地时间设置成功！当前时间：%s" , remotetime);
		return 0;
	}
}

void Show_Localtime()
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	time_t now;
	struct tm* timenow;
	char* ptimestr	= NULL;
	time(&now);
	timenow	= localtime(&now);
	ptimestr	= asctime(timenow);
	if (ptimestr[strlen(ptimestr) - 1] == '\n')
		ptimestr[strlen(ptimestr) - 1] = '\0';
	ccis_log_info("服务器当前本地时间：%s" , ptimestr);
}

static size_t header_callback(char* buffer , size_t size , size_t nitems , void* userdata)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char* res	= strstr(buffer , "Date");
	if (res)
	{
		Set_Localtime(buffer + 6);
		if (res[strlen(res) - 1] == '\n')
			res[strlen(res) - 1] = '\0';
		ccis_log_info("时间服务器当前时间：%s" , buffer + 6);
	}

	return size * nitems;
}

int Get_Remotetime(const char* addr)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	CURL* curl_handle;
	curl_handle	= curl_easy_init();
	if (!curl_handle)
	{
		ccis_log_err("[%s:%d] Curl init failed" , __FUNCTION__ , __LINE__);
		return 1;
	}

	curl_easy_setopt(curl_handle , CURLOPT_URL , addr);
	curl_easy_setopt(curl_handle , CURLOPT_NOPROGRESS , 1L);
	curl_easy_setopt(curl_handle , CURLOPT_NOBODY , 1L);
	curl_easy_setopt(curl_handle , CURLOPT_HEADERFUNCTION , header_callback);
	curl_easy_perform(curl_handle);
	printf("时间同步已执行，对端服务器地址：%s\n" , addr);

	curl_easy_cleanup(curl_handle);
	Show_Localtime();
	return 0;
}

time_t Get_Time_From_String(char* timestr)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	char* pos	= timestr;
	char year[5] , month[3] , day[3] , hour[3] , min[3] , sec[3];

	year[0]	= *pos ++;
	year[1]	= *pos ++;
	year[2]	= *pos ++;
	year[3]	= *pos ++;
	year[4]	= '\0';

	pos ++;

	month[0]	= *pos ++;
	month[1]	= *pos ++;
	month[2]	= '\0';

	pos ++;

	day[0]	= *pos ++;
	day[1]	= *pos ++;
	day[2]	= '\0';

	pos ++;

	hour[0]	= *pos ++;
	hour[1]	= *pos ++;
	hour[2]	= '\0';

	pos ++;

	
	min[0]	= *pos ++;
	min[1]	= *pos ++;
	min[2]	= '\0';

	pos ++;

	sec[0]	= *pos ++;
	sec[1]	= *pos ++;
	sec[2]	= '\0';

	struct tm tmObj;

#ifdef DEBUG
	printf("******字符串转时间*****\n");
	printf("Year\t:%s\n" , year);
	printf("Month\t:%s\n" , month);
	printf("Day\t:%s\n" , day);
	printf("Hour\t:%s\n" , hour);
	printf("Min\t:%s\n" , min);
	printf("Sec\t:%s\n" , sec);
	printf("***********************\n");
#endif

	tmObj.tm_year	= atoi(year) - 1900;
	tmObj.tm_mon	= atoi(month) - 1;
	tmObj.tm_mday	= atoi(day);
	tmObj.tm_hour	= atoi(hour);
	tmObj.tm_min	= atoi(min);
	tmObj.tm_sec	= atoi(sec);
	tmObj.tm_isdst	= -1;

	return mktime(&tmObj);
}

char* Get_String_From_Time(time_t* pstTime)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	struct tm *tmp_ptr	=  localtime(pstTime);

	char *result = malloc(20);
	if (result == NULL)        //0726 patch
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}
	sprintf(result, "%04d/%02d/%02d %02d:%02d:%02d", 1900 + tmp_ptr->tm_year, 1 + tmp_ptr->tm_mon, tmp_ptr->tm_mday,
        	tmp_ptr->tm_hour, tmp_ptr->tm_min, tmp_ptr->tm_sec);
	return result;
}

char* Compute_Days_Before(int days)
{
#ifdef CALLTRACE
	ccis_log_debug("CALLTRACER ：{%s} Is Running..." , __FUNCTION__);
	printf("%s Is Running...\n" , __FUNCTION__);
#endif
	if (days < 1)
		return NULL;
	char* current_date	= Get_Localdate();
	if (!current_date)
	{
		ccis_log_err("无法获取当前日期！");
		return NULL;
	}
	char* tmp_date	= current_date;
	char* result	= NULL;

	int year	= atoi(tmp_date);
	tmp_date	+= 5;
	int month	= atoi(tmp_date);
	tmp_date	+= 3;
	int day		= atoi(tmp_date);

	day	-= days;

	while (day <= 0)
	{
		month --;
		if (month <= 0)
		{
			year --;
			month	= 12;
		}

		if (month == 2)
		{
			if (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0))
				day	+= 29;
			else
				day	+= 28;
		}
		else if (month == 1 || month == 3 || month == 5 || month ==7 || month == 8 || month == 10 || month ==12)
			day	+= 31;
		else
			day	+= 30;
	}

	result	= malloc(sizeof(char) * SECOND_TIME_LEN);
	if (!result)
	{
		ccis_log_emerg("[%s:%d]内存分配失败！失败原因：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		goto clean_up;
	}
	sprintf(result , "%04d/%02d/%02d" , year , month , day);

clean_up:
	if (current_date)
		free(current_date);
	return result;
}
